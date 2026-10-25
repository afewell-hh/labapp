# Hedgehog Lab Appliance

Virtual appliance for Hedgehog Fabric learning and lab exercises.

## Project Status

The GCP appliance is in production for Hedgehog LMS labs and demos. Automated
image builds remain in development.

## Overview

The goal of this project is to provide a virtual appliance that loads into a state that is aligned with the [Hedgehog Fabric learning labs](hedgehog.cloud/learn). The virtual appliance will load into a state that allows users to immediately begin working through the labs without needing to perform initial setup steps.

## Build direction

The goal includes reproducible VM builds for multiple platforms, with GCP as
the current production delivery. The lead selects tools based on source-backed
research and measured fit. Shared guest provisioning and tests should work
with approved image builders, alongside provider-specific lifecycle, access
and guest adaptations. A complete automated image pipeline is not yet implemented.

Additional platform priorities and CPU scope remain open. Disk format conversion
alone does not establish boot compatibility or functional VLAB/nested
virtualization support; x86 and ARM runtime scope require validation before
any compatibility claim. See the [agent workflow](docs/contributing/agent-workflow.md)
for execution, validation and cloud authorization rules.

