import { readFile, writeFile } from 'node:fs/promises';
import { MeshoptEncoder } from 'meshoptimizer/encoder';
import { MeshoptDecoder } from 'three/addons/libs/meshopt_decoder.module.js';

// Pack the Blender export with KHR_meshopt_compression without quantization, filters or reordering.
// Every buffer view decodes, with the browser's own decoder, to the exported bytes.
const EXTENSION = 'KHR_meshopt_compression';
const file = process.argv[2] || 'assets/scene/workstation.glb';
const glb = await readFile(file);
if (glb.readUInt32LE(0) !== 0x46546c67 || glb.readUInt32LE(4) !== 2) throw new Error(`${file} is not a glTF 2.0 binary`);
const jsonLength = glb.readUInt32LE(12);
const json = JSON.parse(glb.subarray(20, 20 + jsonLength));
if (json.extensionsUsed?.includes(EXTENSION)) {
  console.log(`${file} is already packed`);
  process.exit(0);
}
if (json.buffers.length !== 1 || json.buffers[0].uri !== undefined) throw new Error('Expected a single embedded GLB buffer');
const bin = glb.subarray(28 + jsonLength, 28 + jsonLength + glb.readUInt32LE(20 + jsonLength));

await Promise.all([MeshoptEncoder.ready, MeshoptDecoder.ready]);
const components = { SCALAR: 1, VEC2: 2, VEC3: 3, VEC4: 4 }, bytes = { 5120: 1, 5121: 1, 5122: 2, 5123: 2, 5125: 4, 5126: 4 };
const indices = new Set(json.meshes.flatMap(mesh => mesh.primitives.map(primitive => primitive.indices)));
const packed = [];
let offset = 0;
for (const [index, view] of json.bufferViews.entries()) {
  const users = json.accessors.filter(accessor => accessor.bufferView === index);
  const source = bin.subarray(view.byteOffset || 0, (view.byteOffset || 0) + view.byteLength);
  const stride = users.length === 1 ? components[users[0].type] * bytes[users[0].componentType] : 0;
  const count = stride ? users[0].count : 0;
  // INDICES keeps the exact triangle and corner order; TRIANGLES may rotate corners.
  const mode = users.length === 1 && indices.has(json.accessors.indexOf(users[0])) ? 'INDICES' : 'ATTRIBUTES';
  const supported = stride && !users[0].byteOffset && !view.byteStride && view.byteLength === count * stride
    && (mode === 'INDICES' ? stride === 2 || stride === 4 : stride % 4 === 0 && stride <= 256);
  const data = supported ? MeshoptEncoder.encodeGltfBuffer(new Uint8Array(source), count, stride, mode, 1) : source;
  if (supported) {
    const decoded = new Uint8Array(count * stride);
    MeshoptDecoder.decodeGltfBuffer(decoded, count, stride, data, mode, 'NONE');
    if (!Buffer.from(decoded.buffer).equals(source)) throw new Error(`Buffer view ${index} did not decode to its original bytes`);
    view.extensions = { ...view.extensions, [EXTENSION]: { buffer: 0, byteOffset: offset, byteLength: data.length, byteStride: stride, count, mode } };
    view.buffer = 1;
  } else {
    view.byteOffset = offset;
  }
  packed.push(Buffer.from(data.buffer, data.byteOffset, data.byteLength), Buffer.alloc((4 - data.length % 4) % 4));
  offset += Math.ceil(data.length / 4) * 4;
}
// Compressed views keep their original layout in a data-free fallback buffer.
json.buffers = [{ byteLength: offset }, { byteLength: bin.length, extensions: { [EXTENSION]: { fallback: true } } }];
json.extensionsUsed = [...(json.extensionsUsed || []), EXTENSION];
json.extensionsRequired = [...(json.extensionsRequired || []), EXTENSION];

const text = Buffer.from(JSON.stringify(json));
const jsonChunk = Buffer.concat([text, Buffer.alloc((4 - text.length % 4) % 4, 0x20)]);
const binChunk = Buffer.concat(packed);
const header = Buffer.alloc(12);
header.writeUInt32LE(0x46546c67, 0); header.writeUInt32LE(2, 4); header.writeUInt32LE(12 + 8 + jsonChunk.length + 8 + binChunk.length, 8);
const chunk = (type, body) => { const head = Buffer.alloc(8); head.writeUInt32LE(body.length, 0); head.writeUInt32LE(type, 4); return [head, body]; };
await writeFile(file, Buffer.concat([header, ...chunk(0x4e4f534a, jsonChunk), ...chunk(0x004e4942, binChunk)]));
console.log(`Packed ${file}: ${glb.length} → ${12 + 16 + jsonChunk.length + binChunk.length} bytes`);
