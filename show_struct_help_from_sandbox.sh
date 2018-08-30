#!/bin/bash

# This utility script will show you the help provided by the Structural Preprocessing app
# within the HCPprocessingPipelinesSandbox

time singularity exec HCPprocessPipelinesSandbox/ /pipeline_tools/xnat_pbs_jobs/StructuralPreprocessing/StructuralPreprocessing.SINGULARITY_PROCESS --help

