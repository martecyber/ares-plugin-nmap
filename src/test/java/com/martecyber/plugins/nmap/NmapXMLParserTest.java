package com.martecyber.plugins.nmap;

import com.martecyber.ares.assets.AssetLinkType;
import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.AssetMetadataKeys;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;
import com.martecyber.ares.imports.ParsedDetection;
import com.martecyber.ares.imports.parsers.ScannerParserUtils;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Covers {@link NmapXMLParser}: the host/interface/ip asset chain (including the MAC-as-interface-
 * identifier special case), open/filtered/closed port handling, NSE script detections at both the
 * port and host level, and the user &gt; PTR &gt; NETBIOS hostname-hint priority order that keeps
 * host identity stable across a hostname change for the same IP.
 */
class NmapXMLParserTest {

    private static final String XML = """
        <?xml version="1.0"?>
        <nmaprun scanner="nmap" version="7.94">
          <host>
            <status state="up"/>
            <address addr="10.0.0.1" addrtype="ipv4"/>
            <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Dell"/>
            <hostnames>
              <hostname name="myhost.local" type="user"/>
            </hostnames>
            <ports>
              <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http" product="Apache httpd" version="2.4.41"/>
                <script id="http-title" output="Example Domain"/>
              </port>
              <port protocol="tcp" portid="443">
                <state state="filtered"/>
                <service name="https"/>
              </port>
              <port protocol="tcp" portid="22">
                <state state="closed"/>
                <service name="ssh"/>
              </port>
            </ports>
            <hostscript>
              <script id="nbstat" output="NetBIOS name: MYHOST, NetBIOS user: unknown"/>
            </hostscript>
          </host>
          <host>
            <status state="down"/>
            <address addr="10.0.0.2" addrtype="ipv4"/>
          </host>
          <host>
            <status state="up"/>
            <address addr="10.0.0.3" addrtype="ipv4"/>
            <hostnames>
              <hostname name="ptr-host.example.com" type="PTR"/>
            </hostnames>
          </host>
          <host>
            <status state="up"/>
            <address addr="10.0.0.4" addrtype="ipv4"/>
            <hostscript>
              <script id="nbstat" output="NetBIOS name: SRV01, NetBIOS user: unknown"/>
            </hostscript>
          </host>
        </nmaprun>
        """;

    private ParseResult parse() throws Exception {
        return new NmapXMLParser().parse(XML.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void validateAcceptsNmapXmlAndRejectsOther() {
        NmapXMLParser parser = new NmapXMLParser();
        assertTrue(parser.validate(XML.getBytes(StandardCharsets.UTF_8)));
        assertFalse(parser.validate("<not-nmap/>".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void downHostsAreEntirelySkipped() throws Exception {
        ParseResult result = parse();
        assertTrue(result.getAssets().stream().noneMatch(a -> a.getIdentifier().contains("10.0.0.2")));
        assertTrue(result.getDetections().stream().noneMatch(d -> d.getAssetIdentifier().contains("10.0.0.2")));
    }

    @Test
    void emitsHostInterfaceIpChainUsingMacAsInterfaceIdentifierWhenPresent() throws Exception {
        ParseResult result = parse();

        ParsedAsset host = assetOfType(result, AssetType.HOST, "host-10.0.0.1");
        assertEquals(List.of("myhost.local"), host.getMetadata().get(AssetMetadataKeys.HOSTNAME_HINTS_KEY));

        // A real MAC address takes over as the interface's own identifier instead of "iface-{ip}".
        ParsedAsset iface = assetOfType(result, AssetType.INTERFACE, "AA:BB:CC:DD:EE:FF");
        assertEquals("host-10.0.0.1", iface.getMetadata().get("host"));
        assertEquals("AA:BB:CC:DD:EE:FF", iface.getMetadata().get("mac"));

        ParsedAsset ip = assetOfType(result, AssetType.IP, "10.0.0.1");
        assertEquals("AA:BB:CC:DD:EE:FF", ip.getMetadata().get("mac"));

        assertTrue(result.getLinks().stream().anyMatch(l -> l.getFromIdentifier().equals("host-10.0.0.1")
            && l.getToIdentifier().equals("AA:BB:CC:DD:EE:FF") && l.getLinkType().equals(AssetLinkType.HOST_INTERFACE)));
        assertTrue(result.getLinks().stream().anyMatch(l -> l.getFromIdentifier().equals("AA:BB:CC:DD:EE:FF")
            && l.getToIdentifier().equals("10.0.0.1") && l.getLinkType().equals(AssetLinkType.INTERFACE_IP)));
    }

    @Test
    void openPortEmitsServiceAssetAndOpenPortDetection() throws Exception {
        ParseResult result = parse();

        ParsedAsset svc = assetOfType(result, AssetType.SERVICE, "10.0.0.1:80/tcp");
        assertEquals(80, svc.getMetadata().get("port"));
        assertEquals("TCP", svc.getMetadata().get("protocol"));
        assertEquals("http", svc.getMetadata().get("service"));
        assertEquals("Apache httpd", svc.getMetadata().get("product"));
        assertEquals("OPEN", svc.getMetadata().get(ScannerParserUtils.VISIBILITY_STATE_KEY));
        assertTrue(result.getLinks().stream().anyMatch(l -> l.getFromIdentifier().equals("AA:BB:CC:DD:EE:FF")
            && l.getToIdentifier().equals("10.0.0.1:80/tcp") && l.getLinkType().equals(AssetLinkType.INTERFACE_SERVICE)));

        ParsedDetection portDetection = detectionWithTemplate(result, "nmap-open-port-80-tcp");
        assertEquals("Open port 80/tcp (http)", portDetection.getTitle());
        assertEquals("info", portDetection.getSeverity());
        assertEquals("10.0.0.1:80/tcp", portDetection.getAssetIdentifier());
        assertTrue(portDetection.getDescription().contains("Apache httpd"));
    }

    @Test
    void openPortAlsoEmitsOneDetectionPerNseScript() throws Exception {
        ParseResult result = parse();

        ParsedDetection nse = detectionWithTemplate(result, "nmap-nse-http-title");
        assertEquals("NSE: http-title on 10.0.0.1:80/tcp", nse.getTitle());
        assertEquals("Example Domain", nse.getDescription());
        assertEquals("10.0.0.1:80/tcp", nse.getAssetIdentifier());
    }

    @Test
    void filteredPortEmitsServiceButNoOpenPortDetection() throws Exception {
        ParseResult result = parse();

        ParsedAsset svc = assetOfType(result, AssetType.SERVICE, "10.0.0.1:443/tcp");
        assertEquals("FILTERED", svc.getMetadata().get(ScannerParserUtils.VISIBILITY_STATE_KEY));
        assertTrue(result.getDetections().stream().noneMatch(d -> "nmap-open-port-443-tcp".equals(d.getSourceTemplateId())));
    }

    @Test
    void closedPortEmitsNeitherAssetNorDetection() throws Exception {
        ParseResult result = parse();
        assertTrue(result.getAssets().stream().noneMatch(a -> a.getIdentifier().equals("10.0.0.1:22/tcp")));
        assertTrue(result.getDetections().stream().noneMatch(d -> "10.0.0.1:22/tcp".equals(d.getAssetIdentifier())));
    }

    @Test
    void hostLevelScriptDetectionIsAttachedToTheIpNotTheInterface() throws Exception {
        ParseResult result = parse();
        ParsedDetection nbstat = detectionWithTemplate(result, "nmap-nse-host-nbstat");
        assertEquals("NSE: nbstat on 10.0.0.1", nbstat.getTitle());
        assertEquals("10.0.0.1", nbstat.getAssetIdentifier());
    }

    @Test
    void hostnameHintPriorityIsUserThenPtrThenNetbios() throws Exception {
        ParseResult result = parse();

        // Host 1 has both a <user> hostname and an nbstat NETBIOS name — user wins.
        ParsedAsset host1 = assetOfType(result, AssetType.HOST, "host-10.0.0.1");
        assertEquals(List.of("myhost.local"), host1.getMetadata().get(AssetMetadataKeys.HOSTNAME_HINTS_KEY));

        // Host 3 has only a PTR-type <hostname> entry (no user hostname, no nbstat).
        ParsedAsset host3 = assetOfType(result, AssetType.HOST, "host-10.0.0.3");
        assertEquals(List.of("ptr-host.example.com"), host3.getMetadata().get(AssetMetadataKeys.HOSTNAME_HINTS_KEY));

        // Host 4 has neither a user hostname nor a <hostnames> block — falls back to the
        // NETBIOS name extracted from its nbstat script output.
        ParsedAsset host4 = assetOfType(result, AssetType.HOST, "host-10.0.0.4");
        assertEquals(List.of("SRV01"), host4.getMetadata().get(AssetMetadataKeys.HOSTNAME_HINTS_KEY));
    }

    @Test
    void totalDetectionCountMatchesOpenPortsPlusNseScripts() throws Exception {
        ParseResult result = parse();
        // Host 1: open-port(80) + nse(http-title) + host-script(nbstat) = 3. Host 4: host-script(nbstat) = 1.
        assertEquals(4, result.getDetections().size());
    }

    private static ParsedAsset assetOfType(ParseResult result, String type, String identifier) {
        return result.getAssets().stream()
            .filter(a -> type.equals(a.getType()) && identifier.equals(a.getIdentifier()))
            .findFirst()
            .orElseThrow(() -> new AssertionError("No " + type + " asset with identifier " + identifier));
    }

    private static ParsedDetection detectionWithTemplate(ParseResult result, String templateId) {
        return result.getDetections().stream()
            .filter(d -> templateId.equals(d.getSourceTemplateId()))
            .findFirst()
            .orElseThrow(() -> new AssertionError("No detection with sourceTemplateId " + templateId));
    }
}
