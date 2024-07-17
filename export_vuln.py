from tenable.sc import TenableSC

tsc = TenableSC(url='https://sc-instance', access_key='abc', secret_key='def')

findings = tsc.analysis.vulns(('severity', '=', '1,2,3,4'), 
                             ('wasVuln', '=', 'onlyWas'), 
                             tool='wasvulndetail')

with open('scan_results.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Scan ID", "Scan Name", "Plugin ID", "Severity", "IP"])

    for finding in findings:
        scan_id = finding['scan_id']
        scan_name = finding['scan_name']
        plugin_id = finding['pluginID']
        severity = finding['severity']['name']
        ip = finding['ips']

        writer.writerow([scan_id, scan_name, plugin_id, severity, ip])
