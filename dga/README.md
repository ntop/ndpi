# Overview

This folder contains training and inference scripts for two models based on different technologies: MLP (multi-layer perceptron) using scikit-learn and an LSTM-based neural network using TensorFlow. Each model has its own folder with its own training and testing scripts.

The test scripts are only intended to show how to use an already trained model.

## Requirements

To install the necessary dependencies, run

```bash
pip install -r requirements.txt
```

## How to use the scripts

### 1. scikit-learn (MLP model)

**Folder**: `scikit-learn_tests`.

#### Training

To train the MLP model, run the training script:

```bash
python scikit-learn_tests/training_script.py
```

#### Inference

After training, you can perform inference using the test script:

```bash
python scikit-learn_tests/test_script.py
```

### 2. TensorFlow (LSTM model)

**Folder**: `tensorflow_tests`.

#### Training

To train the LSTM model, run the training script

```bash
python tensorflow_tests/training_script.py
```

#### Inference

Once training is complete, you can run inference on the test set with

```bash
python tensorflow_tests/test_script.py
```