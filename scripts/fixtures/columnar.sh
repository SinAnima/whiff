#!/usr/bin/env bash
# Regenerate the columnar and machine-learning fixtures under
# tests/fixtures/<format>/.
#
# Written in two containers run with podman, for a fictitious harbour
# (Saltmere Harbour): tide readings as tables and tiny models with made-up
# weights, CC0-1.0. `whiff-columnar` (Python) runs craft_columnar.py with
# each format's own library: pyarrow (Parquet, Arrow IPC file and stream,
# Feather 1, ORC), pandas (Parquet, pickle), geopandas (GeoParquet), pylance,
# vortex-data, deltalake, pyiceberg (SQL catalog), tfrecord, safetensors,
# gguf, onnx, torch (ZIP and legacy checkpoints), keras / TensorFlow (Keras
# archive, TensorFlow Lite, SavedModel) and coremltools. `whiff-columnar-r`
# runs craft_columnar.R (fst, qs, qs2).
#
#     scripts/fixtures/columnar.sh
#
# Containerfile (`podman build -t whiff-columnar`):
#
#     FROM docker.io/library/python:3.12-slim-bookworm
#     RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates
#     RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch==2.15.0
#     RUN pip install --no-cache-dir pyarrow==26.0.0 pandas==3.1.0 pylance==14.0.2 vortex-data==0.90.0 \
#         deltalake==1.6.6 "pyiceberg[sql-sqlite,pyarrow]==0.12.0" safetensors==0.8.0 numpy==2.5.4 gguf==0.19.0 \
#         onnx==1.23.2 tfrecord==1.14.6 coremltools==9.0 geopandas==1.2.0 shapely==2.2.0 tensorflow==2.21.0
#
# Containerfile (`podman build -t whiff-columnar-r`):
#
#     FROM docker.io/rocker/r-ver:4.4.2
#     RUN Rscript -e 'install.packages(c("fst", "qs2"))' && \
#         Rscript -e 'install.packages("qs", repos = "https://packagemanager.posit.co/cran/2025-01-15")'

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
work=$(mktemp -d "$root/target/columnar-fixtures.XXXXXX")
w="/whiff/${work#"$root"/}"

podman run --rm -v "$root:/whiff" -w /whiff -e TF_CPP_MIN_LOG_LEVEL=3 whiff-columnar sh -euc "
python3 scripts/fixtures/craft_columnar.py $w
python3 scripts/fixtures/craft_columnar.py $w tensorflow
" 2>/dev/null
podman run --rm -v "$root:/whiff" -w /whiff whiff-columnar-r Rscript scripts/fixtures/craft_columnar.R "$w"

# Each folder of the scratch directory is one fixture format.
for d in "$work"/*/; do
    id=$(basename "$d")
    mkdir -p "$fx/$id"
    cp "$d"* "$fx/$id/"
done

source_md() {
    local id=$1 name=$2 origin=$3
    {
        echo "# Fixtures for \`$id\` ($name)"
        echo
        echo "Files made for whiff's tests, CC0-1.0, for a fictitious harbour (Saltmere Harbour): tide readings and tiny models with made-up weights. Regenerate with \`scripts/fixtures/columnar.sh\`."
        echo
        echo "| File | Origin | Licence |"
        echo "|---|---|---|"
        for f in "$fx/$id"/*; do
            [ "$(basename "$f")" = SOURCE.md ] && continue
            echo "| \`$(basename "$f")\` | $origin | CC0-1.0 |"
        done
    } >"$fx/$id/SOURCE.md"
}
source_md parquet "Apache Parquet" "pyarrow 26.0.0 (snappy, row groups of 50) and pandas 3.1.0 (zstd, with index)"
source_md geoparquet "GeoParquet" "geopandas 1.2.0 (GeoParquet 1.1, EPSG:4326 points)"
source_md arrow "Apache Arrow IPC / Feather" "pyarrow 26.0.0 (Feather 2, lz4)"
source_md arrow_stream "Apache Arrow IPC stream" "pyarrow 26.0.0 (three record batches)"
source_md feather_v1 "Feather v1" "pyarrow 26.0.0 (write_feather version=1)"
source_md orc "Apache ORC" "pyarrow 26.0.0 (zstd)"
source_md pandas_pickle "pandas DataFrame pickle" "pandas 3.1.0 DataFrame.to_pickle"
source_md lance "Lance" "pylance 14.0.2 (a data file of a written dataset)"
source_md vortex "Vortex" "vortex-data 0.90.0"
source_md delta_log "Delta Lake transaction log" "deltalake 1.6.6 (partitioned write, then an append)"
source_md iceberg_metadata "Iceberg table metadata" "pyiceberg 0.12.0 (SQL catalog, one append)"
source_md tfrecord "TFRecord / RecordIO" "tfrecord 1.14.6 (tf.train.Example records)"
source_md safetensors "Safetensors" "safetensors 0.8.0 (numpy, with metadata)"
source_md gguf "GGUF / GGML model" "gguf 0.19.0 GGUFWriter (F16 and F32 tensors)"
source_md onnx "ONNX model" "onnx 1.23.2 helper API, checked by onnx.checker"
source_md pytorch "PyTorch checkpoint" "torch 2.15.0 torch.save (ZIP state dict, training checkpoint, legacy format)"
source_md keras "Keras model" "keras 3.15.1 Model.save"
source_md tflite "TensorFlow Lite model" "TensorFlow 2.21.0 TFLiteConverter from the Keras model"
source_md savedmodel "TensorFlow SavedModel" "TensorFlow 2.21.0 Model.export from the Keras model"
source_md mlmodel "Core ML model" "coremltools 9.0 NeuralNetworkBuilder"
source_md fst "R fst table" "R 4.4.2, fst 0.9.8 (compressed and uncompressed)"
source_md qs "R qs / qs2 serialisation" "R 4.4.2, qs 0.27.2 and qs2 0.1.4"
echo "fixtures written; scratch files in $work"
