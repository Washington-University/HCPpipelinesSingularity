#!/bin/bash

# This utility script demonstrates how to test run the Structural Preprocessing Completion
# Check from within the HCPprocessPipelinesSandbox.
#
# This assumes that you have a subdirectory of your home directory named 'data' and that
# subdirectory contains another subdirectory named 'mystudy'. The 'mystudy' directory is
# in standard HCP Pipelines format, with subdirectories for each subject named with the
# subject's ID.
#
# The ${HOME}/data subdirectory is mounted and available within your HCPprocessPipelinesSandbox
# as the /data directory. Thus the --working-dir= specification points to /data/mystudy.

time singularity exec -B ${HOME}/data:/data HCPprocessPipelinesSandbox/ /pipeline_tools/hcp_pipelines_run_utils/StructuralPreprocessing/StructuralPreprocessing.CHECK \
			--subject=100307 \
			--classifier=3T \
			--working-dir=/data/mystudy \
			--verbose

