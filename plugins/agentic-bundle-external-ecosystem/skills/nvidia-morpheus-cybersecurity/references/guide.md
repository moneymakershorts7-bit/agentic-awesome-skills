# NVIDIA Morpheus Pipeline Reference

## Python Pipeline Construction
```python
from morpheus.pipeline import LinearPipeline
from morpheus.stages.input.file_source_stage import FileSourceStage
from morpheus.stages.preprocess.deserialize_stage import DeserializeStage
from morpheus.stages.inference.triton_inference_stage import TritonInferenceStage

pipeline = LinearPipeline()
# Add pipeline stages for real-time telemetry processing
```