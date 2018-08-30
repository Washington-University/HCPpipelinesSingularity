#!/bin/bash

# This utility script will build the HCPprocessPipelines.img Singularity container
# image from the HCPprocessPipelines Singularity recipe file.
#
# This assumes you have sudoer privileges on the system on which you are trying to
# build the container. It also assumes you have Singularity properly installed
# on the system on which you are trying to build the container.

time sudo singularity build HCPprocessPipelines.img HCPprocessPipelines
