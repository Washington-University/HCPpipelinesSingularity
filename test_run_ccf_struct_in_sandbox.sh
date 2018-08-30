#!/bin/bash

# This utility script demonstrates how to test run the Structural Preprocessing from within the
# HCPprocessPipelinesSandbox on a CCF LifeSpan subject.
#
# This assumes that you have a subdirectory of your home directory named 'data' and that
# subdirectory contains another subdirectory named 'mystudy'. The 'mystudy' directory is
# in standard HCP Pipelines format, with subdirectories for each subject named with the
# subject's ID.
#
# The ${HOME}/data subdirectory is mounted and available within your HCPprocessPipelinesSandbox
# as the /data directory. Thus the --working-dir= specification points to /data/mystudy.

time singularity exec -B ${HOME}/data:/data HCPprocessPipelinesSandbox/ /pipeline_tools/hcp_pipelines_run_utils/StructuralPreprocessing/StructuralPreprocessing.SINGULARITY_PROCESS \
			--working-dir=/data/mystudy \
			--subject=HCA6005242 \
			--classifier=V1_MR \
			--brainsize=150 \
			\
			--first-t1w-directory-name=T1w_MPR_vNav_4e_RMS \
			--first-t1w-file-name=HCA6005242_V1_MR_T1w_MPR_vNav_4e_RMS.nii.gz \
			\
			--first-t2w-directory-name=T2w_SPC_vNav \
			--first-t2w-file-name=HCA6005242_V1_MR_T2w_SPC_vNav.nii.gz \
			\
			--t1template=MNI152_T1_0.8mm.nii.gz \
			--t1templatebrain=MNI152_T1_0.8mm_brain.nii.gz \
			--t1template2mm=MNI152_T1_2mm.nii.gz \
			\
			--t2template=MNI152_T2_0.8mm.nii.gz \
			--t2templatebrain=MNI152_T2_0.8mm_brain.nii.gz \
			--t2template2mm=MNI152_T2_2mm.nii.gz \
			\
			--templatemask=MNI152_T1_0.8mm_brain_mask.nii.gz \
			--template2mmmask=MNI152_T1_2mm_brain_mask_dil.nii.gz \
			\
			--fnirtconfig=T1_2_MNI152_2mm.cnf \
			--gdcoeffs=Prisma_3T_coeff_AS82.grad \
			--topupconfig=b02b0.cnf \
			\
			--fieldmap-type=SpinEcho \
			--se-phase-pos=HCA6005242_V1_MR_SpinEchoFieldMap1_PA.nii.gz \
			--se-phase-neg=HCA6005242_V1_MR_SpinEchoFieldMap1_AP.nii.gz



			

			
