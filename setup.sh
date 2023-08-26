#!/bin/bash

FILEDIR=$(pwd)

# Source the Conda configuration
CONDA_BASE=$(conda info --base)
source "$CONDA_BASE/etc/profile.d/conda.sh"

# # Create a new conda environment with Python 3.8
ENV_NAME="myenv"

# Check if the environment already exists
conda info --envs | grep -w "$ENV_NAME" > /dev/null

if [ $? -eq 0 ]; then
   echo "Activating Conda environment $ENV_NAME"
   conda activate "$ENV_NAME"
else
   echo "Creating and activating new Conda environment $ENV_NAME with Python 3.8"
   conda create -n "$ENV_NAME" python=3.8
   conda activate "$ENV_NAME"
fi

# Get the CUDA and cuDNN versions, install pytorch, torchvision

conda run -n "$ENV_NAME" pip install torch==1.9.0 torchvision -f \
  "https://download.pytorch.org/whl/cu111/torch_stable.html"

conda run -n "$ENV_NAME" python -m pip install detectron2 -f \
  https://dl.fbaipublicfiles.com/detectron2/wheels/cu111/torch1.9/index.html

# Install PhishIntention
conda run -n "$ENV_NAME" pip install -v .
package_location=$(conda run -n "$ENV_NAME" pip show phishintention | grep Location | awk '{print $2}')

if [ -z "PhishIntention" ]; then
  echo "Package PhishIntention not found in the Conda environment myenv."
  exit 1
else
  echo "Going to the directory of package PhishIntention in Conda environment myenv."
  cd "$package_location/phishintention" || exit
  git clone https://huggingface.co/Kelsey98/PhishIntention
  cp -r PhishIntention/* src/
  rm -rf PhishIntention
fi

# Replace the placeholder in the YAML template
sed "s|CONDA_ENV_PATH_PLACEHOLDER|$package_location/phishintention|g" "$FILEDIR/phishintention/configs_template.yaml" > "$package_location/phishintention/configs.yaml"
cd "$FILEDIR"
conda run -n "$ENV_NAME" pip install -r requirements.txt
