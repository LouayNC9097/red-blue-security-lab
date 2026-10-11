import pathlib, re, subprocess, sys

msi = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path(
    r"C:\Users\pc\AppData\Local\Temp\wazuh-agent.msi")

# The MSI is an OLE compound file; property names/values live in UTF-16 strings.
raw = msi.read_bytes()
text = raw.decode("utf-16-le", errors="ignore")

wanted = [w for w in re.findall(r"WAZUH[A-Z_]*", text)]
print("WAZUH* property names found in MSI:")
for w in sorted(set(wanted)):
    print("  ", w)

print()
for probe in ["WAZUH_MANAGER", "WAZUH_AGENT_NAME", "WAZUH_AGENT_GROUP",
              "WAZUH_REGISTRATION_SERVER", "WAZUH_REGISTRATION_GROUP"]:
    print(f"{probe:32} present={probe in text}")
