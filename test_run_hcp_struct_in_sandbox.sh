#!/bin/bash

# This utility script demonstrates how to test run the Structural Preprocessing from within the
# HCPprocessPipelinesSandbox on an HCP-YA subject.
#
# This assumes that you have a subdirectory of your home directory named 'data' and that
# subdirectory contains another subdirectory named 'mystudy'. The 'mystudy' directory is
# in standard HCP Pipelines format, with subdirectories for each subject named with the
# subject's ID.
#
# The ${HOME}/data subdirectory is mounted and available within your HCPprocessPipelinesSandbox
# as the /data directory. Thus the --working-dir= specification points to /data/mystudy.

time singularity exec -B ${HOME}/data:/data HCPprocessPipelinesSandbox/ /pipeline_tools/hcp_pipelines_run_utils/StructuralPreprocessing/StructuralPreprocessing.SINGULARITY_PROCESS \
			--subject=100307 \
			--classifier=3T \
			--fieldmap-type=SiemensGradientEcho \
			--working-dir=/data/mystudy \
			\
			--first-t1w-directory-name=T1w_MPR1 \
			--first-t1w-file-name=100307_3T_T1w_MPR1.nii.gz \
			\
			--first-t2w-directory-name=T2w_SPC1 \
			--first-t2w-file-name=100307_3T_T2w_SPC1.nii.gz \
			\
			--t1template=MNI152_T1_0.7mm.nii.gz \
			--t1templatebrain=MNI152_T1_0.7mm_brain.nii.gz \
			--t1template2mm=MNI152_T1_2mm.nii.gz \
			\
			--t2template=MNI152_T2_0.7mm.nii.gz \
			--t2templatebrain=MNI152_T2_0.7mm_brain.nii.gz \
			--t2template2mm=MNI152_T2_2mm.nii.gz \
			\
			--templatemask=MNI152_T1_0.7mm_brain_mask.nii.gz \
			--template2mmmask=MNI152_T1_2mm_brain_mask_dil.nii.gz \
			\
			--fnirtconfig=T1_2_MNI152_2mm.cnf \
			--gdcoeffs=coeff_SC72C_Skyra.grad \
			--topupconfig=b02b0.cnf \
			\
			--brainsize=150
			

			
