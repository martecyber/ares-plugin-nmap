package com.martecyber.plugins.nmap;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.assets.AssetLinkType;
import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.AssetMetadataKeys;
import com.martecyber.ares.imports.ImportParser;
import com.martecyber.ares.imports.parsers.ScannerParserUtils;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;
import com.martecyber.ares.imports.ParsedDetection;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamReader;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class NmapXMLParser implements ImportParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override public String getToolId() { return "nmap"; }
    @Override public String getDisplayName() { return "Nmap XML"; }
    @Override public String[] getSupportedExtensions() { return new String[]{".xml"}; }

    @Override
    public boolean validate(byte[] content) {
        String s = new String(content, StandardCharsets.UTF_8);
        return s.contains("<nmaprun") && s.trim().endsWith("</nmaprun>");
    }

    @Override
    public ParseResult parse(byte[] content) throws Exception {
        ParseResult result = new ParseResult();
        List<NmapHost> hosts = parseXml(content);

        for (NmapHost host : hosts) {
            if (!"up".equals(host.status) || host.ip == null) continue;

            // ── Host ─────────────────────────────────────────────────────────
            // The HOST's parse-time identifier is always "host-{ip}" — an internal join key
            // resolved to the real (possibly pre-existing) host identity by core's own logic.
            // Any hostname found (priority: user hostname > PTR > NETBIOS from nbstat script)
            // is carried as a hint, merged into the resolved host's `hostnames` list rather
            // than driving its identifier — this is what keeps host identity stable across a
            // hostname change for the same IP.
            String hostname = bestHostname(host);
            String hostIdentifier = "host-" + host.ip;

            Map<String, Object> hostMeta = new LinkedHashMap<>();
            if (hostname != null) hostMeta.put(AssetMetadataKeys.HOSTNAME_HINTS_KEY, List.of(hostname));
            result.addAsset(new ParsedAsset(hostIdentifier, AssetType.HOST, hostMeta));

            // ── Interface ────────────────────────────────────────────────────
            String ifaceIdentifier = (host.mac != null && !host.mac.isBlank())
                ? host.mac : "iface-" + host.ip;
            Map<String, Object> ifaceMeta = new LinkedHashMap<>();
            ifaceMeta.put("host", hostIdentifier);
            if (host.mac != null) ifaceMeta.put("mac", host.mac);
            result.addAsset(new ParsedAsset(ifaceIdentifier, AssetType.INTERFACE, ifaceMeta));

            // ── IP ───────────────────────────────────────────────────────────
            result.addAsset(new ParsedAsset(host.ip, AssetType.IP,
                Map.of("mac", host.mac != null ? host.mac : "")));

            // ── Links: host → interface → ip ─────────────────────────────────
            result.addLink(hostIdentifier, ifaceIdentifier, AssetLinkType.HOST_INTERFACE);
            result.addLink(ifaceIdentifier, host.ip,        AssetLinkType.INTERFACE_IP);

            // ── Domain assets for known hostnames ─────────────────────────────
            // Asset only, no domain_a link: Nmap doesn't know the actual DNS record type —
            // this hostname could be a CNAME alias resolved through an intermediate domain,
            // not necessarily an A record on this exact name. Only DNS-record-aware tools
            // (dnsx) create domain_a/domain_aaaa relationships.
            for (String hn : host.hostnames) {
                result.addAsset(new ParsedAsset(hn, AssetType.DOMAIN,
                    Map.of("resolvedIp", host.ip)));
            }

            // ── Services (open + filtered ports) ─────────────────────────────
            // Emit SERVICE assets for open and filtered states so visibility tracking can
            // record the filtered-from-vantage-point case. Closed ports are skipped — a
            // closed port isn't a service worth tracking as an asset.
            for (NmapPort port : host.ports) {
                if (port.state == null) continue;
                boolean isOpen     = "open".equals(port.state) || "open|filtered".equals(port.state);
                boolean isFiltered = "filtered".equals(port.state);
                if (!isOpen && !isFiltered) continue;

                String serviceId = host.ip + ":" + port.port + "/" + port.proto.toLowerCase();
                Map<String, Object> svcMeta = new LinkedHashMap<>();
                svcMeta.put("port",     port.port);
                svcMeta.put("protocol", port.proto);
                svcMeta.put("service",  port.service);
                svcMeta.put("product",  port.product);
                svcMeta.put("version",  port.version);
                // Visibility state — stripped by ImportService before persisting to asset metadata
                svcMeta.put(ScannerParserUtils.VISIBILITY_STATE_KEY,
                    isOpen ? "OPEN" : "FILTERED");
                result.addAsset(new ParsedAsset(serviceId, AssetType.SERVICE, svcMeta));

                // Link: interface → service (the interface exposes this service)
                result.addLink(ifaceIdentifier, serviceId, AssetLinkType.INTERFACE_SERVICE);

                // Only emit the "Open port" detection for actually-open ports —
                // filtered means we couldn't confirm it's listening.
                if (!isOpen) continue;

                String title = "Open port " + port.port + "/" + port.proto.toLowerCase() +
                    (port.service != null ? " (" + port.service + ")" : "");
                String raw;
                try { raw = MAPPER.writeValueAsString(svcMeta); } catch (Exception e) { raw = "{}"; }

                result.addDetection(new ParsedDetection(
                    title, "info", buildPortDescription(port), serviceId,
                    "nmap-open-port-" + port.port + "-" + port.proto.toLowerCase(), raw));

                // NSE script detections
                for (Map.Entry<String, String> script : port.scripts.entrySet()) {
                    String scriptRaw;
                    try { scriptRaw = MAPPER.writeValueAsString(
                        Map.of("script", script.getKey(), "output", script.getValue()));
                    } catch (Exception e) { scriptRaw = "{}"; }
                    result.addDetection(new ParsedDetection(
                        "NSE: " + script.getKey() + " on " + serviceId, "info",
                        script.getValue(), serviceId, "nmap-nse-" + script.getKey(), scriptRaw));
                }
            }

            // ── Host-level script detections ─────────────────────────────────
            for (Map.Entry<String, String> script : host.hostScripts.entrySet()) {
                String scriptRaw;
                try { scriptRaw = MAPPER.writeValueAsString(
                    Map.of("script", script.getKey(), "output", script.getValue()));
                } catch (Exception e) { scriptRaw = "{}"; }
                // detected_at = the IP (most specific known asset for the host)
                result.addDetection(new ParsedDetection(
                    "NSE: " + script.getKey() + " on " + host.ip, "info",
                    script.getValue(), host.ip, "nmap-nse-host-" + script.getKey(), scriptRaw));
            }
        }

        return result;
    }

    /** Best hostname: user-type > PTR > NETBIOS from nbstat script output. */
    private String bestHostname(NmapHost host) {
        if (host.userHostname != null && !host.userHostname.isBlank()) return host.userHostname;
        if (!host.hostnames.isEmpty()) return host.hostnames.get(0);
        if (host.netbiosName != null && !host.netbiosName.isBlank()) return host.netbiosName;
        return null;
    }

    private List<NmapHost> parseXml(byte[] content) throws Exception {
        List<NmapHost> hosts = new ArrayList<>();
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader r = factory.createXMLStreamReader(new ByteArrayInputStream(content));

        NmapHost currentHost = null;
        NmapPort currentPort = null;
        boolean inHostScript = false;

        while (r.hasNext()) {
            int ev = r.next();
            if (ev == XMLStreamConstants.START_ELEMENT) {
                String tag = r.getLocalName();
                switch (tag) {
                    case "host" -> currentHost = new NmapHost();
                    case "address" -> {
                        if (currentHost != null) {
                            String type = r.getAttributeValue(null, "addrtype");
                            String addr = r.getAttributeValue(null, "addr");
                            if ("ipv4".equals(type) || "ipv6".equals(type)) currentHost.ip = addr;
                            else if ("mac".equals(type)) {
                                currentHost.mac = addr;
                                String vendor = r.getAttributeValue(null, "vendor");
                                if (vendor != null) currentHost.macVendor = vendor;
                            }
                        }
                    }
                    case "hostname" -> {
                        if (currentHost != null) {
                            String name = r.getAttributeValue(null, "name");
                            String type = r.getAttributeValue(null, "type");
                            if (name != null && !name.isBlank()) {
                                if ("user".equals(type)) currentHost.userHostname = name;
                                else currentHost.hostnames.add(name);
                            }
                        }
                    }
                    case "status" -> {
                        if (currentHost != null) currentHost.status = r.getAttributeValue(null, "state");
                    }
                    case "port" -> {
                        if (currentHost != null) {
                            currentPort = new NmapPort();
                            String pid = r.getAttributeValue(null, "portid");
                            currentPort.port = pid != null ? Integer.parseInt(pid) : 0;
                            currentPort.proto = Optional.ofNullable(
                                r.getAttributeValue(null, "protocol")).orElse("tcp").toUpperCase();
                        }
                    }
                    case "state" -> {
                        if (currentPort != null) currentPort.state = r.getAttributeValue(null, "state");
                    }
                    case "service" -> {
                        if (currentPort != null) {
                            currentPort.service = r.getAttributeValue(null, "name");
                            currentPort.product = r.getAttributeValue(null, "product");
                            currentPort.version = r.getAttributeValue(null, "version");
                        }
                    }
                    case "hostscript" -> inHostScript = true;
                    case "script" -> {
                        String id  = r.getAttributeValue(null, "id");
                        String out = r.getAttributeValue(null, "output");
                        if (id != null && out != null) {
                            if (inHostScript && currentHost != null) {
                                currentHost.hostScripts.put(id, out);
                                // Extract NETBIOS name from nbstat output
                                if ("nbstat".equals(id) && currentHost.netbiosName == null) {
                                    currentHost.netbiosName = extractNetbiosName(out);
                                }
                            } else if (currentPort != null) {
                                currentPort.scripts.put(id, out);
                            }
                        }
                        consumeElement(r, "script");
                    }
                }
            } else if (ev == XMLStreamConstants.END_ELEMENT) {
                switch (r.getLocalName()) {
                    case "port" -> {
                        if (currentHost != null && currentPort != null) currentHost.ports.add(currentPort);
                        currentPort = null;
                    }
                    case "hostscript" -> inHostScript = false;
                    case "host" -> {
                        if (currentHost != null) hosts.add(currentHost);
                        currentHost = null;
                    }
                }
            }
        }
        r.close();
        return hosts;
    }

    /** Extract NETBIOS name from nbstat script output like "NetBIOS name: MYSERVER, ..." */
    private String extractNetbiosName(String output) {
        if (output == null) return null;
        for (String line : output.split("[\\r\\n]+")) {
            if (line.contains("NetBIOS name:") || line.contains("Name:")) {
                String[] parts = line.split(":");
                if (parts.length > 1) {
                    String name = parts[1].trim().split(",")[0].trim();
                    if (!name.isEmpty() && !name.startsWith("<")) return name;
                }
            }
        }
        return null;
    }

    private void consumeElement(XMLStreamReader r, String tagName) throws Exception {
        int depth = 1;
        while (r.hasNext() && depth > 0) {
            int ev = r.next();
            if (ev == XMLStreamConstants.START_ELEMENT && tagName.equals(r.getLocalName())) depth++;
            else if (ev == XMLStreamConstants.END_ELEMENT && tagName.equals(r.getLocalName())) depth--;
        }
    }

    private String buildPortDescription(NmapPort port) {
        StringBuilder sb = new StringBuilder();
        sb.append("Port ").append(port.port).append("/").append(port.proto.toLowerCase())
          .append(" is ").append(port.state);
        if (port.service != null) sb.append(" — service: ").append(port.service);
        if (port.product != null) sb.append(", product: ").append(port.product);
        if (port.version != null) sb.append(" ").append(port.version);
        return sb.toString();
    }

    private static class NmapHost {
        String ip, mac, macVendor, status, userHostname, netbiosName;
        List<String> hostnames = new ArrayList<>();
        List<NmapPort> ports = new ArrayList<>();
        Map<String, String> hostScripts = new LinkedHashMap<>();
    }

    private static class NmapPort {
        int port; String proto, state, service, product, version;
        Map<String, String> scripts = new LinkedHashMap<>();
    }
}
