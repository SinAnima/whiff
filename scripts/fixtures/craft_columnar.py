"""Columnar and machine-learning fixtures for whiff.

Run by scripts/fixtures/columnar.sh inside the `whiff-columnar` container:

    python3 craft_columnar.py OUT_DIR

Every file is written by the library that owns its format, for a
fictitious harbour (Saltmere Harbour): tide readings as tables, and tiny
models with made-up weights. All CC0-1.0.
"""

import json
import os
import shutil
import sys
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.feather as feather
import pyarrow.orc as orc
import pyarrow.parquet as pq

OUT = sys.argv[1]
T0 = datetime(2025, 9, 1, 6, 0, tzinfo=timezone.utc)


def out(*p):
    path = os.path.join(OUT, *p)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return path


def readings(n=120):
    rng = np.random.default_rng(7)
    return pa.table({
        "station": pa.array([["Saltmere Pier", "North Mole", "Lock Gate"][i % 3] for i in range(n)]).dictionary_encode(),
        "at": pa.array([T0.timestamp() * 1000 + 600_000 * i for i in range(n)], pa.timestamp("ms", tz="UTC")),
        "height_m": pa.array(np.round(2.5 + 1.8 * np.sin(np.arange(n) / 12.0) + rng.normal(0, 0.05, n), 3)),
        "flags": pa.array([[i % 2, i % 5] for i in range(n)], pa.list_(pa.int32())),
        "gauge": pa.array([{"id": f"G{7 + i % 3}", "ok": i % 11 != 0} for i in range(n)],
                          pa.struct([("id", pa.string()), ("ok", pa.bool_())])),
    })


def columnar():
    t = readings()
    t = t.replace_schema_metadata({"harbour": "Saltmere Harbour", "source": "tide gauges"})
    pq.write_table(t, out("parquet", "readings-snappy.parquet"), row_group_size=50, compression="snappy")
    df = t.to_pandas()
    df.to_parquet(out("parquet", "readings-pandas-zstd.parquet"), compression="zstd", index=True)
    feather.write_feather(t, out("arrow", "readings.arrow"), compression="lz4")
    with pa.ipc.new_stream(out("arrow_stream", "readings.arrows"), t.schema) as w:
        for b in t.to_batches(max_chunksize=40):
            w.write_batch(b)
    flat = t.drop_columns(["flags", "gauge"]).cast(pa.schema([
        ("station", pa.string()), ("at", pa.timestamp("ms", tz="UTC")), ("height_m", pa.float64())]))
    feather.write_feather(flat.to_pandas(), out("feather_v1", "readings-v1.feather"), version=1)
    orc.write_table(t.drop_columns(["station"]), out("orc", "readings.orc"), compression="zstd")
    df.to_pickle(out("pandas_pickle", "readings.pkl"))


def geoparquet():
    import geopandas as gpd
    from shapely.geometry import Point

    g = gpd.GeoDataFrame(
        {"berth": [4, 7, 12], "name": ["Pier 4", "Mole 7", "Gate 12"]},
        geometry=[Point(-1.5021, 50.7123), Point(-1.5011, 50.7131), Point(-1.4998, 50.7140)],
        crs="EPSG:4326",
    )
    g.to_parquet(out("geoparquet", "berths.parquet"))


def lance_and_vortex():
    import lance

    t = readings(40).drop_columns(["station"])
    d = os.path.join(OUT, "_scratch", "lance")
    shutil.rmtree(d, ignore_errors=True)
    lance.write_dataset(t, d)
    files = sorted(os.listdir(os.path.join(d, "data")))
    shutil.copy(os.path.join(d, "data", files[0]), out("lance", "readings.lance"))
    import vortex as vx

    vx.io.write(vx.array(readings(40).drop_columns(["station", "flags", "gauge"])), out("vortex", "readings.vortex"))


def tables():
    from deltalake import write_deltalake

    d = os.path.join(OUT, "_scratch", "delta")
    shutil.rmtree(d, ignore_errors=True)
    t = readings(30).drop_columns(["flags", "gauge"]).cast(pa.schema([
        ("station", pa.string()), ("at", pa.timestamp("us", tz="UTC")), ("height_m", pa.float64())]))
    write_deltalake(d, t, partition_by=["station"], name="tides", description="Saltmere tide readings")
    write_deltalake(d, t, mode="append")
    for f in sorted(os.listdir(os.path.join(d, "_delta_log"))):
        if f.endswith(".json"):
            shutil.copy(os.path.join(d, "_delta_log", f), out("delta_log", f))

    from pyiceberg.catalog.sql import SqlCatalog

    wh = "/tmp/saltmere-warehouse"
    shutil.rmtree(wh, ignore_errors=True)
    os.makedirs(wh)
    cat = SqlCatalog("saltmere", uri=f"sqlite:///{wh}/catalog.db", warehouse=f"file://{wh}")
    cat.create_namespace("harbour")
    tbl = cat.create_table("harbour.tides", schema=t.schema, properties={"owner": "harbour-office"})
    tbl.append(t)
    jsons = sorted(os.path.join(d, f) for d, _, fs in os.walk(wh) for f in fs if f.endswith(".metadata.json"))
    shutil.copy(jsons[-1], out("iceberg_metadata", "v2.metadata.json"))


def records():
    from tfrecord.writer import TFRecordWriter

    w = TFRecordWriter(out("tfrecord", "readings.tfrecord"))
    for i in range(25):
        w.write({
            "station": (b"Saltmere Pier", "byte"),
            "height_m": (2.5 + 0.1 * i, "float"),
            "seq": (i, "int"),
        })
    w.close()


def ml():
    from safetensors.numpy import save_file

    rng = np.random.default_rng(3)
    save_file(
        {"encoder.weight": rng.standard_normal((16, 8)).astype(np.float32),
         "encoder.bias": np.zeros(16, np.float32),
         "head.weight": rng.standard_normal((2, 16)).astype(np.float16)},
        out("safetensors", "tide-net.safetensors"),
        metadata={"format": "np", "model": "tide-net", "licence": "CC0-1.0"},
    )

    import gguf

    w = gguf.GGUFWriter(out("gguf", "tide-tiny.gguf"), "llama")
    w.add_name("Tide Tiny")
    w.add_description("A made-up two-layer model for whiff's tests.")
    w.add_license("CC0-1.0")
    w.add_context_length(256)
    w.add_embedding_length(16)
    w.add_block_count(2)
    w.add_feed_forward_length(32)
    w.add_head_count(2)
    w.add_file_type(gguf.LlamaFileType.MOSTLY_F16)
    w.add_tokenizer_model("llama")
    w.add_token_list(["<unk>", "<s>", "</s>", "tide", "berth", "mole"])
    for i in range(2):
        w.add_tensor(f"blk.{i}.attn_q.weight", rng.standard_normal((16, 16)).astype(np.float16))
        w.add_tensor(f"blk.{i}.ffn_up.weight", rng.standard_normal((32, 16)).astype(np.float32))
    w.add_tensor("token_embd.weight", rng.standard_normal((6, 16)).astype(np.float32))
    w.write_header_to_file()
    w.write_kv_data_to_file()
    w.write_tensors_to_file()
    w.close()

    import onnx
    from onnx import TensorProto, helper, numpy_helper

    wts = numpy_helper.from_array(rng.standard_normal((4, 8)).astype(np.float32), "W")
    bias = numpy_helper.from_array(np.zeros(8, np.float32), "B")
    graph = helper.make_graph(
        [helper.make_node("MatMul", ["x", "W"], ["xw"]), helper.make_node("Add", ["xw", "B"], ["h"]),
         helper.make_node("Relu", ["h"], ["y"])],
        "tide_head",
        [helper.make_tensor_value_info("x", TensorProto.FLOAT, ["batch", 4])],
        [helper.make_tensor_value_info("y", TensorProto.FLOAT, ["batch", 8])],
        [wts, bias],
    )
    model = helper.make_model(graph, producer_name="saltmere-exporter", producer_version="1.0",
                              opset_imports=[helper.make_opsetid("", 18)])
    model.doc_string = "Tide head: a linear layer and ReLU."
    model.model_version = 3
    helper.set_model_props(model, {"author": "Saltmere Harbour", "licence": "CC0-1.0"})
    onnx.checker.check_model(model)
    onnx.save(model, out("onnx", "tide-head.onnx"))

    import torch

    torch.manual_seed(1)
    net = torch.nn.Sequential(torch.nn.Linear(4, 8), torch.nn.ReLU(), torch.nn.Linear(8, 2))
    torch.save(net.state_dict(), out("pytorch", "tide-net.pt"))
    opt = torch.optim.SGD(net.parameters(), lr=0.1)
    torch.save({"epoch": 12, "model": net.state_dict(), "optimizer": opt.state_dict()},
               out("pytorch", "checkpoint.ckpt"))
    torch.save(net.state_dict(), out("pytorch", "tide-net-legacy.pth"), _use_new_zipfile_serialization=False)

    coreml(rng)


def tensorflow_models():
    """Keras, TensorFlow Lite and SavedModel: a separate process, since
    TensorFlow and the tfrecord package register the same protobuf types."""
    import keras
    import tensorflow as tf

    keras.utils.set_random_seed(5)
    km = keras.Sequential([keras.Input((4,), name="levels"), keras.layers.Dense(8, activation="relu"),
                           keras.layers.Dense(2, name="tide")], name="tide_net")
    km.save(out("keras", "tide-net.keras"))
    conv = tf.lite.TFLiteConverter.from_keras_model(km)
    open(out("tflite", "tide-net.tflite"), "wb").write(conv.convert())
    sm = os.path.join(OUT, "_scratch", "savedmodel")
    shutil.rmtree(sm, ignore_errors=True)
    km.export(sm)
    shutil.copy(os.path.join(sm, "saved_model.pb"), out("savedmodel", "saved_model.pb"))


def coreml(rng):
    import coremltools as ct
    from coremltools.models import datatypes
    from coremltools.models.neural_network import NeuralNetworkBuilder

    b = NeuralNetworkBuilder([("levels", datatypes.Array(4))], [("tide", datatypes.Array(2))])
    b.add_inner_product("dense", rng.standard_normal((2, 4)).astype(np.float32), np.zeros(2, np.float32), 4, 2,
                        True, "levels", "tide")
    m = ct.models.MLModel(b.spec)
    m.author = "Saltmere Harbour"
    m.license = "CC0-1.0"
    m.short_description = "Tide head as a Core ML neural network."
    m.version = "1.2"
    m.save(out("mlmodel", "TideHead.mlmodel"))


STEPS = {"columnar": columnar, "geoparquet": geoparquet, "lance": lance_and_vortex, "tables": tables,
         "records": records, "ml": ml, "tensorflow": tensorflow_models}

if __name__ == "__main__":
    # Steps by name (default: all but `tensorflow`, which needs its own process).
    for name in sys.argv[2:] or [k for k in STEPS if k != "tensorflow"]:
        STEPS[name]()
    shutil.rmtree(os.path.join(OUT, "_scratch"), ignore_errors=True)
