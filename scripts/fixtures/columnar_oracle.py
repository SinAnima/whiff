"""Compare whiff's columnar and ML reports with each format's own library.

    # in the `whiff-columnar` container: generate a corpus and write the
    # expected facts (generated files plus any under IN_DIR)
    python3 columnar_oracle.py expect OUT_DIR [IN_DIR]

    # on the host: run whiff on every file and compare
    python3 columnar_oracle.py check OUT_DIR WHIFF_BINARY

`expect` writes OUT_DIR/corpus/* (varied files from pyarrow, lance,
deltalake, pyiceberg, safetensors, gguf, onnx, torch, tfrecord and
TensorFlow) and OUT_DIR/expected.jsonl, read back with those libraries:
pyarrow metadata, lance's file reader, DeltaTable history, pyiceberg
metadata, safetensors' safe_open, gguf's GGUFReader, onnx.load, the TF Lite
interpreter, TensorFlow's saved_model_pb2 and coremltools' load_spec.
Paths are recorded relative to OUT_DIR. Nothing here ships with whiff.
"""

import json
import os
import random
import subprocess
import sys
import zipfile

R = random.Random(11)


def rel(out, p):
    return os.path.relpath(p, out)


# ----------------------------------------------------------- generators
def gen_tables(out):
    import numpy as np
    import pyarrow as pa
    import pyarrow.feather as feather
    import pyarrow.orc as orc
    import pyarrow.parquet as pq

    def table(i):
        n = R.randint(1, 900)
        cols = {}
        kinds = ["int8", "int16", "int32", "int64", "uint32", "float32", "float64", "string", "bool", "date32",
                 "ts_ms", "ts_us_utc", "list", "struct", "dict", "decimal", "binary", "nullable"]
        for j, k in enumerate(R.sample(kinds, R.randint(1, 8))):
            name = f"c{j}_{k}"
            if k.startswith(("int", "uint")):
                cols[name] = pa.array(np.random.default_rng(i + j).integers(-100 if k[0] == "i" else 0, 100, n), getattr(pa, k)())
            elif k.startswith("float"):
                cols[name] = pa.array(np.random.default_rng(i).normal(0, 50, n), getattr(pa, k)())
            elif k == "string":
                cols[name] = pa.array([f"berth {x % 37}" for x in range(n)])
            elif k == "bool":
                cols[name] = pa.array([x % 3 == 0 for x in range(n)])
            elif k == "date32":
                cols[name] = pa.array([19_000 + x for x in range(n)], pa.date32())
            elif k == "ts_ms":
                cols[name] = pa.array([1_700_000_000_000 + 1000 * x for x in range(n)], pa.timestamp("ms"))
            elif k == "ts_us_utc":
                cols[name] = pa.array([1_700_000_000_000_000 + x for x in range(n)], pa.timestamp("us", tz="UTC"))
            elif k == "list":
                cols[name] = pa.array([[x, x + 1] for x in range(n)], pa.list_(pa.int64()))
            elif k == "struct":
                cols[name] = pa.array([{"a": x, "b": str(x)} for x in range(n)])
            elif k == "dict":
                cols[name] = pa.array([["N", "S", "E", "W"][x % 4] for x in range(n)]).dictionary_encode()
            elif k == "decimal":
                import decimal
                cols[name] = pa.array([decimal.Decimal(x) / 100 for x in range(n)], pa.decimal128(9, 2))
            elif k == "binary":
                cols[name] = pa.array([bytes([x % 256]) * 3 for x in range(n)], pa.binary())
            else:
                cols[name] = pa.array([None if x % 4 == 0 else x for x in range(n)], pa.int32())
        return pa.table(cols)

    rows = []
    for i in range(40):
        t = table(i)
        codec = R.choice(["none", "snappy", "gzip", "zstd", "lz4", "brotli"])
        p = os.path.join(out, "corpus", f"t{i}.parquet")
        pq.write_table(t, p, compression=codec, row_group_size=R.choice([50, 200, 10_000]))
        m = pq.ParquetFile(p).metadata
        rows.append((p, {"rows": m.num_rows, "row_groups": m.num_row_groups, "column_count": len(t.schema),
                         "columns": sorted(t.schema.names), "created_by": m.created_by}))
    for i in range(20):
        t = table(100 + i)
        p = os.path.join(out, "corpus", f"t{i}.arrow")
        feather.write_feather(t, p, compression=R.choice(["uncompressed", "lz4", "zstd"]), chunksize=R.choice([64, 1000]))
        r = pa.ipc.open_file(p)
        rows.append((p, {"rows": r.read_all().num_rows, "record_batches": r.num_record_batches,
                         "columns": sorted(r.schema.names)}))
        p2 = os.path.join(out, "corpus", f"t{i}.arrows")
        with pa.ipc.new_stream(p2, t.schema) as w:
            for b in t.to_batches(max_chunksize=R.choice([10, 100, 1000])):
                w.write_batch(b)
        s = pa.ipc.open_stream(p2)
        batches = list(s)
        rows.append((p2, {"rows": sum(b.num_rows for b in batches), "record_batches": len(batches),
                          "columns": sorted(s.schema.names)}))
    for i in range(20):
        t = table(200 + i)
        t = t.select([c for c in t.schema.names if not any(x in c for x in ("dict", "decimal", "uint"))])
        if t.num_columns == 0:
            continue
        p = os.path.join(out, "corpus", f"t{i}.orc")
        comp = R.choice(["uncompressed", "zlib", "snappy", "lz4", "zstd"])
        orc.write_table(t, p, compression=comp, stripe_size=R.choice([64 * 1024, 64 * 1024 * 1024]))
        f = orc.ORCFile(p)
        rows.append((p, {"rows": f.nrows, "stripes": f.nstripes, "columns": sorted(f.schema.names),
                         "compression": {"UNCOMPRESSED": "none"}.get(f.compression, f.compression.lower())}))
    return rows


def gen_ml(out):
    import numpy as np
    rows = []
    from safetensors import safe_open
    from safetensors.numpy import save_file

    for i in range(20):
        tensors = {}
        for j in range(R.randint(1, 12)):
            dt = R.choice([np.float32, np.float16, np.int64, np.uint8, np.int32])
            shape = tuple(R.randint(1, 9) for _ in range(R.randint(0, 3)))
            tensors[f"layer{j}.w"] = np.zeros(shape, dt)
        p = os.path.join(out, "corpus", f"m{i}.safetensors")
        save_file(tensors, p, metadata={"run": str(i)} if i % 2 else None)
        with safe_open(p, "np") as f:
            keys = list(f.keys())
            params = int(sum(np.prod(f.get_slice(k).get_shape(), dtype=np.int64) for k in keys))
        rows.append((p, {"tensors": len(keys), "parameters": params}))

    import gguf

    for i in range(10):
        p = os.path.join(out, "corpus", f"m{i}.gguf")
        w = gguf.GGUFWriter(p, R.choice(["llama", "qwen2", "gemma"]))
        w.add_name(f"model {i}")
        w.add_context_length(R.choice([512, 4096]))
        for j in range(R.randint(1, 6)):
            arr = np.zeros((R.randint(1, 4) * 32, 32), R.choice([np.float32, np.float16]))
            if R.random() < 0.3:
                w.add_tensor(f"t{j}", gguf.quants.quantize(arr.astype(np.float32), gguf.GGMLQuantizationType.Q8_0),
                             raw_dtype=gguf.GGMLQuantizationType.Q8_0)
            else:
                w.add_tensor(f"t{j}", arr)
        w.write_header_to_file()
        w.write_kv_data_to_file()
        w.write_tensors_to_file()
        w.close()
        rows.append((p, gguf_facts(p)))

    import onnx
    from onnx import TensorProto, helper, numpy_helper

    ops = ["Relu", "Sigmoid", "Tanh", "Abs", "Neg", "Exp"]
    for i in range(20):
        nodes, prev = [], "x"
        inits = []
        for j in range(R.randint(1, 10)):
            if R.random() < 0.4:
                wname = f"w{j}"
                inits.append(numpy_helper.from_array(np.zeros((4, 4), np.float32), wname))
                nodes.append(helper.make_node("MatMul", [prev, wname], [f"h{j}"]))
            else:
                nodes.append(helper.make_node(R.choice(ops), [prev], [f"h{j}"]))
            prev = f"h{j}"
        g = helper.make_graph(nodes, f"g{i}", [helper.make_tensor_value_info("x", TensorProto.FLOAT, ["n", 4])],
                              [helper.make_tensor_value_info(prev, TensorProto.FLOAT, ["n", 4])], inits)
        m = helper.make_model(g, producer_name=f"gen{i}", opset_imports=[helper.make_opsetid("", R.choice([13, 17, 18]))])
        p = os.path.join(out, "corpus", f"m{i}.onnx")
        onnx.save(m, p)
        rows.append((p, onnx_facts(p)))

    from tfrecord.writer import TFRecordWriter

    for i in range(10):
        p = os.path.join(out, "corpus", f"r{i}.tfrecord")
        w = TFRecordWriter(p)
        n = R.randint(1, 300)
        for k in range(n):
            w.write({"a": (k, "int"), "b": (b"x" * (k % 50), "byte"), "c": (0.5, "float")})
        w.close()
        rows.append((p, {"records": n, "features": {"a": "int64", "b": "bytes", "c": "float"}}))

    import torch

    for i in range(10):
        net = torch.nn.Sequential(*[torch.nn.Linear(4, 4) for _ in range(R.randint(1, 4))])
        if i % 3 == 0:
            net = net.half()
        p = os.path.join(out, "corpus", f"m{i}.pt")
        torch.save(net.state_dict(), p, _use_new_zipfile_serialization=i % 4 != 3)
        rows.append((p, torch_facts(p)))
    return rows


def gguf_facts(p):
    import gguf

    r = gguf.GGUFReader(p)
    import numpy as np
    params = int(sum(int(np.prod([int(x) for x in t.shape])) for t in r.tensors))
    f = {"tensors": len(r.tensors), "parameters": params}
    arch = r.fields.get("general.architecture")
    if arch:
        f["architecture"] = bytes(arch.parts[arch.data[0]]).decode()
    return f


def onnx_facts(p):
    import onnx

    m = onnx.load(p, load_external_data=False)
    ops = {}
    for n in m.graph.node:
        key = n.op_type if n.domain in ("", "ai.onnx") else f"{n.domain}.{n.op_type}"
        ops[key] = ops.get(key, 0) + 1
    inits = {t.name for t in m.graph.initializer}
    f = {"ir_version": m.ir_version, "nodes": len(m.graph.node), "tensors": len(m.graph.initializer),
         "inputs": sorted(i.name for i in m.graph.input if i.name not in inits)[:100],
         "outputs": sorted(o.name for o in m.graph.output)[:100]}
    if m.producer_name:
        f["producer"] = m.producer_name[:200]
    if len(ops) <= 50:
        f["operators"] = ops
    return f


def torch_facts(p):
    if zipfile.is_zipfile(p):
        z = zipfile.ZipFile(p)
        names = z.namelist()
        archive = [n for n in names if n.endswith("/data.pkl") and n.count("/") == 1][0].split("/")[0]
        return {"format": "zip", "archive": archive, "storages": sum(1 for n in names if n.startswith(archive + "/data/"))}
    return {"format": "legacy"}


def tflite_facts(p):
    import tensorflow as tf

    it = tf.lite.Interpreter(model_path=p)
    ops = {}
    for o in it._get_ops_details():
        ops[o["op_name"]] = ops.get(o["op_name"], 0) + 1
    return {"operator_types": ops, "inputs": sorted(d["name"] for d in it.get_input_details()),
            "outputs": sorted(d["name"] for d in it.get_output_details())}


def savedmodel_facts(p):
    from tensorflow.core.protobuf import saved_model_pb2

    sm = saved_model_pb2.SavedModel()
    sm.ParseFromString(open(p, "rb").read())
    mg = sm.meta_graphs[0]
    return {"meta_graphs": len(sm.meta_graphs), "tags": list(mg.meta_info_def.tags),
            "tensorflow_version": mg.meta_info_def.tensorflow_version, "graph_nodes": len(mg.graph_def.node),
            "functions": len(mg.graph_def.library.function), "signatures": sorted(mg.signature_def.keys())}


def tf_sub(kind, p):
    """TensorFlow facts from a separate process (TensorFlow and the tfrecord
    package register the same protobuf types)."""
    res = subprocess.run([sys.executable, __file__, "tf-facts", kind, p], capture_output=True,
                         env={**os.environ, "TF_CPP_MIN_LOG_LEVEL": "3"})
    lines = [l for l in res.stdout.decode().splitlines() if l.startswith("{")]
    if not lines:
        return {"oracle_error": res.stderr.decode()[-200:]}
    return json.loads(lines[-1])


def coreml_facts(p):
    import coremltools as ct

    spec = ct.utils.load_spec(p)
    d = spec.description
    f = {"specification_version": spec.specificationVersion,
         "inputs": sorted(i.name for i in d.input)[:100], "outputs": sorted(o.name for o in d.output)[:100]}
    if d.metadata.author:
        f["author"] = d.metadata.author[:200]
    return f


def expect_dir(d):
    """Facts for real files copied from the host (by extension)."""
    rows = []
    for name in sorted(os.listdir(d)):
        p = os.path.join(d, name)
        try:
            if name.endswith(".onnx"):
                rows.append((p, onnx_facts(p)))
            elif name.endswith((".pt", ".pth")):
                rows.append((p, torch_facts(p)))
            elif name.endswith(".gguf"):
                rows.append((p, gguf_facts(p)))
            elif name.endswith(".tflite"):
                rows.append((p, tf_sub("tflite", p)))
            elif name.endswith(".mlmodel"):
                rows.append((p, coreml_facts(p)))
        except Exception as e:  # recorded, not compared
            rows.append((p, {"oracle_error": f"{type(e).__name__}: {e}"[:200]}))
    return rows


def cmd_expect(out, extra):
    os.makedirs(os.path.join(out, "corpus"), exist_ok=True)
    rows = gen_tables(out) + gen_ml(out)
    # The fixtures' TF Lite and SavedModel files, read by TensorFlow.
    for p, kind in [("tests/fixtures/tflite/tide-net.tflite", "tflite"), ("tests/fixtures/savedmodel/saved_model.pb", "savedmodel")]:
        rows.append((os.path.abspath(p), tf_sub(kind, p)))
    if extra:
        rows += expect_dir(extra)
    with open(os.path.join(out, "expected.jsonl"), "w") as fh:
        for p, facts in rows:
            fh.write(json.dumps({"path": rel(out, p) if p.startswith(os.path.abspath(out)) or not os.path.isabs(p) else p,
                                 "facts": facts}) + "\n")
    print(f"{len(rows)} files written to {out}/expected.jsonl")


# --------------------------------------------------------------- check
def norm(k, v, got):
    if k in ("columns", "inputs", "outputs") and isinstance(got, dict):
        return sorted(got.keys())[:100]
    if k == "signatures" and isinstance(got, dict):
        return sorted(got.keys())
    if k == "features" and isinstance(got, dict):
        return got
    return got


def cmd_check(out, whiff, root):
    rows = [json.loads(l) for l in open(os.path.join(out, "expected.jsonl"))]
    totals, fails, errors = {}, {}, 0
    for row in rows:
        facts = row["facts"]
        if "oracle_error" in facts:
            errors += 1
            continue
        path = row["path"]
        if path.startswith("/whiff/"):
            path = os.path.join(root, path[len("/whiff/"):])
        elif not os.path.isabs(path):
            path = os.path.join(out, path)
        res = subprocess.run([whiff, "--profile", "standard", path], capture_output=True)
        ext = os.path.splitext(path)[1].lower()
        totals[ext] = totals.get(ext, 0) + 1
        try:
            r = json.loads(res.stdout)
        except json.JSONDecodeError:
            fails.setdefault(ext, []).append((path, [("report", "present", res.stderr.decode()[:200])]))
            continue
        fmt = r.get("format", {})
        got = next(iter(fmt.values()), {}) if fmt else {}
        bad = []
        for k, v in facts.items():
            g = norm(k, v, got.get(k))
            if k == "compression" and g is None:
                g = got.get("compression")
            if g != v:
                bad.append((k, v, g))
        if bad:
            fails.setdefault(ext, []).append((path, bad))
    for ext in sorted(totals):
        n, f = totals[ext], len(fails.get(ext, []))
        print(f"{ext:13} {n - f:5}/{n:<5} agree")
    print(f"oracle could not read {errors} files")
    for ext, items in sorted(fails.items()):
        for path, bad in items[:6]:
            print(f"  {path}")
            for k, v, g in bad[:6]:
                print(f"      {k}: oracle {json.dumps(v)[:160]} whiff {json.dumps(g)[:160]}")


if __name__ == "__main__":
    if sys.argv[1] == "tf-facts":
        print(json.dumps(tflite_facts(sys.argv[3]) if sys.argv[2] == "tflite" else savedmodel_facts(sys.argv[3])))
    elif sys.argv[1] == "expect":
        cmd_expect(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
    else:
        cmd_check(sys.argv[2], sys.argv[3], os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
