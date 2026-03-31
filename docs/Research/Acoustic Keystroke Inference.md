---
title: Acoustic Keystroke Inference from Single-Channel Audio
slug: /Research/Acoustic-Keystroke-Inference
sidebar_position: 2
custom_edit_url: null
---

**Author:** 0x0w1z  
**Type:** Applied security research / acoustic keystroke study

## Abstract

This paper presents a practical acoustic side-channel attack against keyboard input using only single-channel waveform recordings. The analysis uses a long labeled reference capture containing repeated keystrokes across the alphabet and a short unlabeled capture containing the target secret. The recovery pipeline consists of keystroke event detection, handcrafted feature extraction, supervised classification, and sequence decoding. A Random Forest classifier trained on the reference data achieves perfect in-sample separation and recovers the target sequence from the unknown sample. The final recovered sequence is `[redacted token]`.

This exercise demonstrates that even low-cost audio observations can leak sensitive typed content when attacker-controlled calibration data is available.

## 1. Introduction

Keyboard acoustic emanations remain a realistic side-channel risk in shared or surveilled environments. Even when input is not visible, physical keypresses produce location-dependent sounds that can be modeled and classified.

In this study, the objective was to infer a hidden keystroke sequence from controlled recordings:

- `Reference.wav`: repeated labeled keypresses for all alphabet keys in known order
- `target.wav`: an unknown keystroke sequence containing the target payload

The goal was to reconstruct the hidden sequence and recover the final output.

## 2. Dataset and Threat Model

### 2.1 Audio Characteristics

- Channel configuration: mono
- Sampling rate: 44.1 kHz
- Reference duration: approximately 304.6 seconds
- Target duration: approximately 12.2 seconds

### 2.2 Label Structure

The reference file encodes the 26 alphabet keys in QWERTY-order grouping:

`qwertyuiopasdfghjklzxcvbnm`

Each key appears 50 times, for an expected total of 1300 labeled keystrokes.

### 2.3 Assumptions

The analysis assumes:

- The same keyboard profile is used for both recordings
- Noise conditions remain relatively stable
- Keystrokes are temporally separable through short-frame energy peaks

These assumptions are consistent with many controlled side-channel experiments and make direct supervised learning viable.

## 3. Methodology

### 3.1 Keystroke Detection

The waveform is segmented into 10 ms frames and short-time energy is computed per frame. Candidate keystrokes are then selected through peak detection with the following parameters:

- Threshold: `median(energy) * 5`
- Minimum peak distance: 150 ms

Detected events:

- Reference: 1305 peaks
- Target: 19 peaks

The reference count is close to the expected 1300, indicating that the detector is well aligned with the recording structure.

### 3.2 Feature Engineering

For each detected event, a 60 ms local window is extracted and converted into a 160-dimensional handcrafted feature vector:

- 128 FFT-magnitude aggregate bins for frequency structure
- 32 amplitude-envelope bins for temporal shape

This representation is intentionally lightweight while still capturing enough information to separate individual keys.

### 3.3 Supervised Learning

Reference events are labeled sequentially using the known key ordering and repetition count. A Random Forest model is trained on the resulting dataset with the following setup:

- Model: Random Forest
- Trees: 200
- Preprocessing: standard scaling

Training accuracy reaches `1.000`, which indicates very strong class separability under this controlled dataset.

### 3.4 Decoding Procedure

The same detection and feature-extraction pipeline is applied to `target.wav`. Predicted labels from the trained classifier are concatenated in event order to recover the hidden plaintext.

## 4. Results

Predicted 19-character sequence:

`ohyougotthisfardamn`

Representative per-keystroke confidence scores stay consistently high, roughly between 76% and 97%, which supports the stability of the recovered sequence across the target sample.

Recovered output:

`[redacted output]`

## 5. Discussion

This case study reinforces three practical points:

1. Acoustic side channels can be highly exploitable when attacker-labeled calibration data is available.
2. Classical features combined with tree-based models can be sufficient; deep learning is not strictly necessary in controlled environments.
3. Keyboard acoustics should be treated as potentially sensitive telemetry in operational settings.

## 6. Limitations

- The evaluation is dataset-specific and not cross-keyboard validated.
- The method was not stress-tested under adversarial noise, microphone variation, or inconsistent typing force.
- The reported training accuracy is in-sample, so generalization under domain shift remains unmeasured.

## 7. Conclusion

The hidden keystroke sequence was successfully reconstructed from acoustic data using a compact machine-learning pipeline. The result is a practical demonstration that keyboard acoustic emanations remain a relevant side-channel risk when clean calibration data is available.

## References

1. D. Asonov and R. Agrawal, "Keyboard Acoustic Emanations," 2004 IEEE Symposium on Security and Privacy.
2. "A Practical Implementation of Keyboard Acoustic Side-Channel Attacks," arXiv:2308.01074.
