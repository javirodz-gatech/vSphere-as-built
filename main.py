import ssl
from pyvim.connect import SmartConnect, Disconnect
from pyVmomi import vim
from datetime import datetime
import OpenSSL


def vcenter_configuration_information(si, vcenter_hostname):
    print(f'\033[31mvCenter Configuration Information:\033[0m')
    # Get the vCenter Server version and build number
    about = si.content.about
    version = about.version
    build_number = about.build
    name = about.name

    # Print the vCenter Server information
    print(f'vCenter Server Hostname:\t{vcenter_hostname}')
    print(f'vCenter Server version:\t\t{about.fullName}')
    print(f'vCenter Server OS type:\t\t{about.osType}')



def vcenter_license(si):
    print(f'\033[31mvCenter Licenses:\033[0m')
    # Get the LicenseAssignmentManager object
    license_assignment_manager = si.content.licenseManager.licenseAssignmentManager

    # Get the license assignments
    license_assignments = license_assignment_manager.QueryAssignedLicenses()

    # Print the license information
    for assignment in license_assignments:
        # print(assignment)
        print(f'Host: {assignment.entityDisplayName}', end=" => ")
        print(f"License name: {assignment.assignedLicense.name}", end=" => ")
        print(f"License key: {assignment.assignedLicense.licenseKey}")
        # print(f"License key #: {assignment.assignedLicense.total}")
        # print(f"License edition: {assignment.assignedLicense.editionKey}")


def vcenter_cert_expiration(host):
    print(f'\033[31mvCenter Certificate Expiration Date:\033[0m')
    host = "vs-vcenter-01.hanbury.network"
    # retrieve SSL client certificate information
    cert = ssl.get_server_certificate((host, 443))
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    bytes = x509.get_notAfter()
    # print(bytes)
    timestamp = bytes.decode('utf-8')
    expiration_date = datetime.strptime(timestamp, '%Y%m%d%H%M%S%z').date().isoformat()
    print(f'Machine SSL Certificate Expiration: {expiration_date}')


def main():
    # Disable SSL certificate verification
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    vcenter_hostname = "vs-vcenter-01"
    # Connect to vSphere
    try:
        si = SmartConnect(
            host="vs-vcenter-01.hanbury.network",
            user="administrator@vsphere.local",
            pwd="P@ssw0rd!@2022",
            sslContext=context
        )
    except Exception as e:
        print(f"Failed to connect to vCenter Server: {e}")
        exit()

    # Print vCenter Information
    vcenter_configuration_information(si, vcenter_hostname)
    exit(0)
    # Print Licensing Information
    vcenter_license(si)

    # Print Certificate Expiration Date
    vcenter_cert_expiration(si)

    # Print vCenter Permissions
    vcenter_permissions(si)

    # Print vCenter Resource Pools
    vcenter_resource_pools(si)

    # Get the root folder of the vSphere inventory
    root_folder = si.content.rootFolder

    # Get a list of datacenter objects
    datacenters = root_folder.childEntity

    # Loop through the datacenters
    for dc in datacenters:
        # Get the host folder of the datacenter
        host_folder = dc.hostFolder

        # Get a list of cluster objects
        clusters = host_folder.childEntity

        # Loop through the clusters
        for cluster in clusters:
            # Get a list of host systems
            hosts = cluster.host
            # Get info from the cluster
            cluster_info(cluster)

    # Print the names of the hosts
    print("Datacenter:", dc.name, "=> Cluster:", cluster.name)
    print(f"\033[31mHosts in cluster {cluster.name}:\033[0m")
    for host in hosts:
        print(f'\t\033[32m{host.name}\033[0m')

        print(f"\t\tStorage Adapters on {host.name}:")
        storage_system = host.configManager.storageSystem
        storage_adapters = storage_system.storageDeviceInfo.hostBusAdapter
        for adapter in storage_adapters:
            if adapter.status != "unknown" and adapter.model == "iSCSI Software Adapter":
                print(f"\t\t\t- {adapter.device}")
                print(f"\t\t\t  Model: {adapter.model}")
                # print(f"\t\t\t  Driver: {adapter.driver}")
                # print(f"\t\t\t  Status: {adapter.status}")
                print(f"\t\t\t  IQN: {adapter.iScsiName}")
                # Get the list of configured static targets
                configured_static_targets = adapter.configuredStaticTarget
                # Print the configured static targets
                for target in configured_static_targets:
                    print(f'\t\t\t  Static target: {target.address}:{target.port}')

        # Get the network configuration of the host
        network_config = host.config.network

        # Print the domain name for the host
        print("\t\tFQDN:")
        print(f"\t\t\t{host.summary.config.name}")

        # Print the DNS configuration for the host
        print("\t\tDNS Configuration:")
        for dns in network_config.dnsConfig.address:
            print(f"\t\t\tDNS Server: {dns}")

        # Print the NTP configuration for the host
        print("\t\tNTP Configuration:")
        for ntp in host.config.dateTimeInfo.ntpConfig.server:
            print(f"\t\t\tNTP Server: {ntp}")

        # Get a list of vSwitches on the host
        vswitches = network_config.vswitch

        # Print the names of the vSwitches
        for vswitch in vswitches:
            print("\t\tvSwitch:", vswitch.name)
            print("\t\t\tUplink:")
            for uplink in vswitch.pnic:
                print("\t\t\t\t", uplink)  # uplink.split("-")[2]
            # Get a list of port group objects on the vSwitch
            portgroups = vswitch.portgroup
            # Print the names of the port groups
            print("\t\t\tPort Group:")
            for pg in portgroups:
                print(f'\t\t\t\t{pg}')

        # Get a list of vmkernel adapter configurations on the host
        vmk_configs = network_config.vnic
        # Print the names of the vmkernel adapters
        print("\t\tVMkernel Adapters:")
        for vmk_config in vmk_configs:
            if isinstance(vmk_config.spec, vim.host.VirtualNic.Specification):
                print("\t\t\tName:", vmk_config.device, "\tIP Address:", vmk_config.spec.ip.ipAddress)

        # Get the host file system volume info
        datastores = host.configManager.storageSystem.fileSystemVolumeInfo.mountInfo
        print("\t\tDatastores:")
        # Loop through the datastores
        for datastore in datastores:
            if datastore.volume.type != "OTHER":
                print(f'\t\t\tName: {datastore.volume.name}\tCapacity: {datastore.volume.capacity / (1024 ** 3):.2f} GB', end="\t")
                print(f"of Type: {datastore.volume.type}")

        host_vm_list(host)

        # break  # During testing, I will only print the info of one Host. Comment the break to list all hosts.

    # Disconnect from vSphere
    Disconnect(si)


def host_vm_list(host_obj):
    # Get the list of VMs on the host
    vms = host_obj.vm

    # Print the host name and the list of VMs
    print(f'\t\tVMs:')
    for vm in vms:
        print(f'\t\t\t- {vm.name}')


def cluster_info(cluster_obj):
    print(f'\033[31mCluster Information:\033[0m')
    # Get cluster HA configuration
    ha_config = cluster_obj.configurationEx.dasConfig
    print(f'HA Configuration Enabled:\t{ha_config.enabled}')
    print(f'Admission Control Enabled:\t{ha_config.admissionControlEnabled}')

    # Get cluster DRS configuration
    drs_config = cluster_obj.configurationEx.drsConfig
    print(f'DRS Configuration Enabled:\t{drs_config.enabled}')

    # Get the EVC manager for the cluster
    evc_manager = cluster_obj.EvcManager()

    # Get the current EVC mode and baseline
    evc_mode = evc_manager.evcState.currentEVCModeKey
    print(f'Current EVC mode:\t\t\t{evc_mode}')

    # Print DRS rules for the cluster
    config_ex = cluster_obj.configurationEx
    for rule in config_ex.rule:
        # if isinstance(rule, vim.cluster.VmHostRuleInfo):
        #    print(f"DRS rule: {rule.name}, VMs: {', '.join(vm.name for vm in rule.vm)}")
        print(f'Rule name:\t\t\t\t{rule.name}')
        print(f'\tEnabled:\t\t\t{rule.enabled}')
        print(f'\tMandatory\t\t\t{rule.mandatory}')
        print(f'Groups configured in:\t{rule.name}')
        print(f'\tVM Group Name:\t\t{rule.vmGroupName}')
        print(f'\tHost Group Name:\t{rule.affineHostGroupName}')
    for group in config_ex.group:
        if group.name == rule.vmGroupName or group.name == rule.affineHostGroupName:
            if isinstance(group, vim.cluster.HostGroup):
                host_names = [host.name for host in group.host]
                print(f"Host Group: {group.name}\n\tMembers:\t{', '.join(host_names)}")
            if isinstance(group, vim.cluster.VmGroup):
                vm_names = [vm.name for vm in group.vm]
                print(f"VM group: {group.name},\n\tMembers:\t{', '.join(vm_names)}")


def vcenter_permissions(si):
    print(f'\033[31mvCenter Permissions:\033[0m')
    # Get the authorization manager for the vCenter Server
    auth_manager = si.content.authorizationManager

    # Get the list of roles
    roles = auth_manager.roleList

    # Create an empty dictionary to store the role name and ID
    role_dict = {}

    # Loop through each role and add it to the dictionary
    for role in roles:
        role_dict[role.roleId] = role.name

    # Print the dictionary
    # print(role_dict)

    # Get the list of permissions
    permissions = auth_manager.RetrieveAllPermissions()
    # Print the name and role of each user or group with a permission on the vCenter Server
    for permission in permissions:
        # print(permission)
        principal = permission.principal
        print(f'{principal}, Role: {role_dict[permission.roleId]}, Propagate to children?: {permission.propagate}')


def vcenter_resource_pools(si):
    # Get the root folder of the vCenter Server
    root_folder = si.content.rootFolder

    # Get the list of compute resources in the vCenter Server
    compute_resources = root_folder.childEntity

    # Loop through each compute resource and print the name, memory usage, memory limit, and CPU usage for each resource pool
    for compute_resource in compute_resources:
        if hasattr(compute_resource, 'resourcePool'):
            resource_pool = compute_resource.resourcePool
            print(f"Compute resource: {compute_resource.name}")
            for child in resource_pool.resourcePool:
                if hasattr(child, 'name'):
                    print(f"Resource pool: {child.name}")
                    print(f"  Memory usage: {child.summary.quickStats.hostMemoryUsage / 1024 / 1024} MB")
                    print(f"  Memory limit: {child.summary.config.memoryAllocation.limit / 1024 / 1024} MB")
                    print(f"  CPU usage: {child.summary.quickStats.overallCpuUsage} MHz")


if __name__ == "__main__":

    main()

