#!/bin/bash
# create-ova.sh
# Convert QEMU VMDK to OVA format
# Part of Hedgehog Lab Appliance build pipeline

set -euo pipefail

# Environment variables passed from Packer
VM_NAME="${VM_NAME:-hedgehog-lab-standard}"
OUTPUT_DIR="${OUTPUT_DIR:-output}"
MEMORY="${MEMORY:-16384}"
CPUS="${CPUS:-8}"
VERSION="${VERSION:-0.1.0}"

echo "=================================================="
echo "Creating OVA from VMDK..."
echo "=================================================="

cd "$OUTPUT_DIR"

# Verify VMDK exists
if [ ! -f "${VM_NAME}.vmdk" ]; then
    echo "ERROR: VMDK file not found: ${VM_NAME}.vmdk"
    exit 1
fi

# Get VMDK file size
VMDK_SIZE=$(stat -c%s "${VM_NAME}.vmdk")
VMDK_SIZE_MB=$((VMDK_SIZE / 1024 / 1024))

echo "VMDK file: ${VM_NAME}.vmdk (${VMDK_SIZE_MB} MB)"

# Create OVF descriptor
cat > "${VM_NAME}.ovf" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<Envelope vmw:buildId="build-0000000" xmlns="http://schemas.dmtf.org/ovf/envelope/1" xmlns:cim="http://schemas.dmtf.org/wbem/wscim/1/common" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1" xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData" xmlns:vmw="http://www.vmware.com/schema/ovf" xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <References>
    <File ovf:href="${VM_NAME}.vmdk" ovf:id="file1" ovf:size="${VMDK_SIZE}"/>
  </References>
  <DiskSection>
    <Info>Virtual disk information</Info>
    <Disk ovf:capacity="100" ovf:capacityAllocationUnits="byte * 2^30" ovf:diskId="vmdisk1" ovf:fileRef="file1" ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized" ovf:populatedSize="${VMDK_SIZE}"/>
  </DiskSection>
  <NetworkSection>
    <Info>The list of logical networks</Info>
    <Network ovf:name="VM Network">
      <Description>The VM Network network</Description>
    </Network>
  </NetworkSection>
  <VirtualSystem ovf:id="${VM_NAME}">
    <Info>A virtual machine</Info>
    <Name>Hedgehog Lab Appliance</Name>
    <OperatingSystemSection ovf:id="100" vmw:osType="ubuntu64Guest">
      <Info>The kind of installed guest operating system</Info>
      <Description>Ubuntu Linux (64-bit)</Description>
    </OperatingSystemSection>
    <VirtualHardwareSection>
      <Info>Virtual hardware requirements</Info>
      <System>
        <vssd:ElementName>Virtual Hardware Family</vssd:ElementName>
        <vssd:InstanceID>0</vssd:InstanceID>
        <vssd:VirtualSystemIdentifier>${VM_NAME}</vssd:VirtualSystemIdentifier>
        <vssd:VirtualSystemType>vmx-14</vssd:VirtualSystemType>
      </System>
      <Item>
        <rasd:AllocationUnits>hertz * 10^6</rasd:AllocationUnits>
        <rasd:Description>Number of Virtual CPUs</rasd:Description>
        <rasd:ElementName>${CPUS} virtual CPU(s)</rasd:ElementName>
        <rasd:InstanceID>1</rasd:InstanceID>
        <rasd:ResourceType>3</rasd:ResourceType>
        <rasd:VirtualQuantity>${CPUS}</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits>
        <rasd:Description>Memory Size</rasd:Description>
        <rasd:ElementName>${MEMORY}MB of memory</rasd:ElementName>
        <rasd:InstanceID>2</rasd:InstanceID>
        <rasd:ResourceType>4</rasd:ResourceType>
        <rasd:VirtualQuantity>${MEMORY}</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:Address>0</rasd:Address>
        <rasd:Description>SCSI Controller</rasd:Description>
        <rasd:ElementName>SCSI Controller 0</rasd:ElementName>
        <rasd:InstanceID>3</rasd:InstanceID>
        <rasd:ResourceSubType>lsilogic</rasd:ResourceSubType>
        <rasd:ResourceType>6</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:AddressOnParent>0</rasd:AddressOnParent>
        <rasd:ElementName>Hard Disk 1</rasd:ElementName>
        <rasd:HostResource>ovf:/disk/vmdisk1</rasd:HostResource>
        <rasd:InstanceID>4</rasd:InstanceID>
        <rasd:Parent>3</rasd:Parent>
        <rasd:ResourceType>17</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:AddressOnParent>0</rasd:AddressOnParent>
        <rasd:AutomaticAllocation>true</rasd:AutomaticAllocation>
        <rasd:Connection>VM Network</rasd:Connection>
        <rasd:Description>VmxNet3 ethernet adapter on "VM Network"</rasd:Description>
        <rasd:ElementName>Network adapter 1</rasd:ElementName>
        <rasd:InstanceID>5</rasd:InstanceID>
        <rasd:ResourceSubType>VmxNet3</rasd:ResourceSubType>
        <rasd:ResourceType>10</rasd:ResourceType>
      </Item>
    </VirtualHardwareSection>
    <ProductSection>
      <Info>Product Information</Info>
      <Product>Hedgehog Lab Appliance</Product>
      <Vendor>Hedgehog</Vendor>
      <Version>${VERSION}</Version>
      <FullVersion>${VERSION}</FullVersion>
      <ProductUrl>https://github.com/YOUR_ORG/hedgehog-lab-appliance</ProductUrl>
      <VendorUrl>https://github.com/YOUR_ORG</VendorUrl>
    </ProductSection>
    <AnnotationSection>
      <Info>Custom annotation</Info>
      <Annotation>Hedgehog Lab Appliance - Virtual appliance for Hedgehog Fabric learning and lab exercises.

Version: ${VERSION}
Build Type: Standard

System Requirements:
- CPU: 8 cores (minimum 4)
- RAM: 16GB (minimum 8GB)
- Disk: 100GB
- Network: 1 adapter

Default Credentials:
- Username: hhlab
- Password: hhlab

After first boot, the appliance will initialize automatically (15-20 minutes).
Use 'hh-lab status' to check initialization progress.
</Annotation>
    </AnnotationSection>
  </VirtualSystem>
</Envelope>
EOF

echo "OVF descriptor created: ${VM_NAME}.ovf"

# Create manifest file
echo "Creating manifest..."
sha256sum "${VM_NAME}.vmdk" > "${VM_NAME}.mf"
sha256sum "${VM_NAME}.ovf" >> "${VM_NAME}.mf"

echo "Manifest created: ${VM_NAME}.mf"

# Create OVA (tar archive)
echo "Creating OVA archive..."
tar -cf "${VM_NAME}.ova" "${VM_NAME}.ovf" "${VM_NAME}.mf" "${VM_NAME}.vmdk"

# Verify OVA was created
if [ -f "${VM_NAME}.ova" ]; then
    OVA_SIZE=$(stat -c%s "${VM_NAME}.ova")
    OVA_SIZE_MB=$((OVA_SIZE / 1024 / 1024))
    echo "OVA created successfully: ${VM_NAME}.ova (${OVA_SIZE_MB} MB)"

    # Clean up intermediate files
    rm -f "${VM_NAME}.ovf" "${VM_NAME}.mf"

    echo ""
    echo "=================================================="
    echo "OVA creation complete!"
    echo "=================================================="
    echo "File: ${OUTPUT_DIR}/${VM_NAME}.ova"
    echo "Size: ${OVA_SIZE_MB} MB"
    echo ""
else
    echo "ERROR: Failed to create OVA"
    exit 1
fi
