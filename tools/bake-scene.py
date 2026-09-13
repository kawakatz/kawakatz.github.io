import json
import math
import subprocess
import sys
from pathlib import Path

import bpy
import bmesh
import numpy as np
from mathutils import Vector
from mathutils.kdtree import KDTree

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / '.scene-build'
OUT = ROOT / 'assets/scene'
parts = json.loads(BUILD.joinpath('source.json').read_text())
has_room = any(part['name'] == 'room-plinth' for part in parts)
room_only = '--room-only' in sys.argv
if room_only:
    assert has_room and BUILD.joinpath('workstation.blend').is_file(), 'Room-only bake requires the previous full bake'
    assert OUT.joinpath('desk-daylight.jpg').is_file() and OUT.joinpath('desk-occlusion.jpg').is_file(), 'Previous desk textures are missing'
bpy.ops.wm.read_factory_settings(use_empty=True)
scene = bpy.context.scene
scene.render.engine = 'CYCLES'
scene.cycles.samples = 256
scene.cycles.use_denoising = True
scene.cycles.max_bounces = 8
scene.cycles.diffuse_bounces = 5
scene.render.threads_mode = 'FIXED'
scene.render.threads = 6
prefs = bpy.context.preferences.addons['cycles'].preferences
prefs.compute_device_type = 'METAL'
prefs.get_devices()
for device in prefs.devices:
    device.use = device.type == 'METAL'
scene.cycles.device = 'GPU'
scene.view_settings.view_transform = 'AgX'
scene.world = bpy.data.worlds.new('Daylight studio')
scene.world.use_nodes = True
scene.world.node_tree.nodes['Background'].inputs[0].default_value = (.68, .75, .86, 1)
scene.world.node_tree.nodes['Background'].inputs[1].default_value = .18


def area(name, position, target, power, size, color):
    data = bpy.data.lights.new(name, 'AREA')
    data.energy = power
    data.shape = 'DISK'
    data.size = size
    data.color = color
    light = bpy.data.objects.new(name, data)
    scene.collection.objects.link(light)
    light.location = position
    light.rotation_euler = (Vector(target) - light.location).to_track_quat('-Z', 'Y').to_euler()


if has_room:
    area('Window daylight', (-2.0, -.40, 2.15), (.3, -.4, .7), 260, 1.30, (.72, .86, 1.0))
    area('Warm reflected daylight', (1.7, -1.3, 3.4), (0, -.1, .8), 160, 2.1, (1.0, .80, .58))
    area('Ceiling bounce', (.1, -1.35, 3.0), (.3, -.9, .6), 85, 2.8, (1.0, .86, .69))
    area('Desk screen bounce', (-.25245, .28, 1.03), (-.25245, -.04, .77), 2.8, .7, (.55, .76, 1.0))
else:
    area('Large window left', (-2.5, -1.3, 3.1), (0, 0, .7), 340, 1.3, (1.0, .82, .64))
    area('Cool fill', (2.0, .9, 2.8), (0, 0, .7), 125, 1.8, (.58, .74, 1.0))
    area('Screen bounce', (-.13, .15, 1.1), (-.13, -.2, .8), 7, .85, (.55, .71, 1.0))
    area('Soft edge light', (1.3, 1.5, 2.3), (0, -.3, .65), 150, 1.3, (1.0, .66, .57))
materials = {}


def room_part(obj):
    name = obj.data.materials[0].name
    return has_room and (name.startswith(('room-', 'bed-', 'pillow-', 'linen-')) or name in ['window-light', 'aircon-vent'] or obj.name.startswith(('desk-controller-', 'desk-extension-')) or obj.name in ('mouse-power-dc-cable', 'mouse-power-ac-cable'))


def material(spec, dynamic=False):
    key = json.dumps(spec) + str(dynamic)
    if key in materials:
        return materials[key]
    mat = bpy.data.materials.new(spec['name'] or f'material-{len(materials)}')
    mat.use_nodes = True
    nodes, links = mat.node_tree.nodes, mat.node_tree.links
    bsdf = nodes.get('Principled BSDF')
    bsdf.inputs['Base Color'].default_value = (*spec['color'], 1)
    bsdf.inputs['Roughness'].default_value = spec['roughness']
    bsdf.inputs['Metallic'].default_value = spec['metalness']
    if spec['name'] in ['chair-graphite', 'chair-chassis']:
        grain = nodes.new('ShaderNodeTexNoise'); grain.inputs['Scale'].default_value = 2400; grain.inputs['Detail'].default_value = 1
        bump = nodes.new('ShaderNodeBump'); bump.inputs['Strength'].default_value = .12; bump.inputs['Distance'].default_value = .00004
        links.new(grain.outputs['Fac'], bump.inputs['Height']); links.new(bump.outputs[0], bsdf.inputs['Normal'])
    if spec['name'] in ['oak', 'room-floor', 'bed-walnut']:
        tex = nodes.new('ShaderNodeTexImage')
        tex.image = bpy.data.images.load(str(ROOT / 'tools/materials/oak-albedo-refined.png'), check_existing=True)
        tex.projection = 'FLAT'
        coords = nodes.new('ShaderNodeNewGeometry')
        mapping = nodes.new('ShaderNodeVectorMath'); mapping.operation = 'MULTIPLY'
        mapping.inputs[1].default_value = (1 / 1.8, 1 / .7, 4) if spec['name'] == 'oak' else (2.7, .46, 3)
        offset = nodes.new('ShaderNodeVectorMath'); offset.operation = 'ADD'
        offset.inputs[1].default_value = (.5, .5, 0)
        if spec['name'] == 'room-floor':
            # Three's long floorboard Z becomes Blender Y. Image U follows the wood grain.
            separate = nodes.new('ShaderNodeSeparateXYZ'); combine = nodes.new('ShaderNodeCombineXYZ')
            links.new(coords.outputs['Position'], separate.inputs[0])
            links.new(separate.outputs['Y'], combine.inputs['X'])
            links.new(separate.outputs['X'], combine.inputs['Y'])
            links.new(separate.outputs['Z'], combine.inputs['Z'])
            mapping.inputs[1].default_value = (.46, 2.7, 3)
            links.new(combine.outputs[0], mapping.inputs[0])
        else:
            links.new(coords.outputs['Position'], mapping.inputs[0])
        links.new(mapping.outputs[0], offset.inputs[0]); links.new(offset.outputs[0], tex.inputs['Vector'])
        links.new(tex.outputs['Color'], bsdf.inputs['Base Color'])
        bump = nodes.new('ShaderNodeBump'); bump.inputs['Strength'].default_value = .12; bump.inputs['Distance'].default_value = .0003
        links.new(tex.outputs['Color'], bump.inputs['Height']); links.new(bump.outputs[0], bsdf.inputs['Normal'])
        if spec['name'] == 'bed-walnut':
            tint = nodes.new('ShaderNodeMixRGB'); tint.blend_type = 'MULTIPLY'; tint.inputs[0].default_value = .8; tint.inputs[2].default_value = (.24, .17, .13, 1)
            links.new(tex.outputs['Color'], tint.inputs[1]); links.new(tint.outputs[0], bsdf.inputs['Base Color'])
    if spec['name'] in ['bed-linen', 'pillow-linen', 'bed-upholstery', 'room-curtain', 'room-bed-curtain']:
        coords = nodes.new('ShaderNodeTexCoord')
        mapping = nodes.new('ShaderNodeVectorMath'); mapping.operation = 'SCALE'; mapping.inputs[3].default_value = 3.333
        links.new(coords.outputs['Generated'], mapping.inputs[0])
        normal_tex = nodes.new('ShaderNodeTexImage'); normal_tex.image = bpy.data.images.load(str(ROOT / 'tools/materials/linen-normal.jpg'), check_existing=True); normal_tex.image.colorspace_settings.name = 'Non-Color'; normal_tex.projection = 'BOX'; normal_tex.projection_blend = .2
        rough_tex = nodes.new('ShaderNodeTexImage'); rough_tex.image = bpy.data.images.load(str(ROOT / 'tools/materials/linen-roughness.jpg'), check_existing=True); rough_tex.image.colorspace_settings.name = 'Non-Color'; rough_tex.projection = 'BOX'; rough_tex.projection_blend = .2
        for tex in [normal_tex, rough_tex]: links.new(mapping.outputs[0], tex.inputs['Vector'])
        normal = nodes.new('ShaderNodeNormalMap'); normal.inputs['Strength'].default_value = .23
        links.new(normal_tex.outputs['Color'], normal.inputs['Color']); links.new(normal.outputs[0], bsdf.inputs['Normal']); links.new(rough_tex.outputs['Color'], bsdf.inputs['Roughness'])
        bsdf.inputs['Sheen Weight'].default_value = .25
        if spec['name'] in ['room-curtain', 'room-bed-curtain']:
            bsdf.inputs['Subsurface Weight'].default_value = .08
    if spec['name'] == 'room-plaster':
        noise = nodes.new('ShaderNodeTexNoise'); noise.inputs['Scale'].default_value = 280; noise.inputs['Detail'].default_value = 2
        bump = nodes.new('ShaderNodeBump'); bump.inputs['Strength'].default_value = .16; bump.inputs['Distance'].default_value = .0013
        links.new(noise.outputs['Fac'], bump.inputs['Height']); links.new(bump.outputs[0], bsdf.inputs['Normal'])
    if spec['name'] == 'window-light':
        bsdf.inputs['Emission Color'].default_value = (*spec['color'], 1)
        bsdf.inputs['Emission Strength'].default_value = .3
    if spec['name'] in ['power-led', 'mouse-status-led']:
        bsdf.inputs['Emission Color'].default_value = (*spec['color'], 1)
        bsdf.inputs['Emission Strength'].default_value = 1.2
    if spec['name'] == 'woven':
        noise = nodes.new('ShaderNodeTexNoise'); noise.inputs['Scale'].default_value = 750; noise.inputs['Detail'].default_value = 1
        bump = nodes.new('ShaderNodeBump'); bump.inputs['Strength'].default_value = .23; bump.inputs['Distance'].default_value = .00045
        links.new(noise.outputs['Fac'], bump.inputs['Height']); links.new(bump.outputs[0], bsdf.inputs['Normal'])
        bsdf.inputs['Base Color'].default_value = (.030, .032, .030, 1)
        bsdf.inputs['Roughness'].default_value = .74
        bsdf.inputs['Sheen Weight'].default_value = .35
        coords = nodes.new('ShaderNodeUVMap'); coords.uv_map = 'DetailUV'
        wave = nodes.new('ShaderNodeTexWave'); wave.bands_direction = 'X'
        wave.inputs['Scale'].default_value = 150
        links.new(coords.outputs['UV'], wave.inputs['Vector'])
        ramp = nodes.new('ShaderNodeValToRGB')
        ramp.color_ramp.elements[0].color = (.023, .025, .023, 1)
        ramp.color_ramp.elements[1].color = (.030, .032, .030, 1)
        links.new(wave.outputs['Color'], ramp.inputs[0]); links.new(ramp.outputs[0], bsdf.inputs['Base Color'])
        # Match desk.js's subpixel weave holes: 6/8 by 3/8 of the fabric passes light.
        rays = nodes.new('ShaderNodeLightPath')
        openness = nodes.new('ShaderNodeMath'); openness.operation = 'MULTIPLY'; openness.inputs[1].default_value = 18 / 64
        links.new(rays.outputs['Is Shadow Ray'], openness.inputs[0])
        transparent = nodes.new('ShaderNodeBsdfTransparent')
        shadow = nodes.new('ShaderNodeMixShader')
        links.new(openness.outputs[0], shadow.inputs[0]); links.new(bsdf.outputs[0], shadow.inputs[1]); links.new(transparent.outputs[0], shadow.inputs[2])
        links.new(shadow.outputs[0], nodes.get('Material Output').inputs['Surface'])
    if spec['name'] in ['straw-plastic', 'straw-inner']:
        bsdf.inputs['Alpha'].default_value = .55 if spec['name'] == 'straw-plastic' else .30
    if spec['name'] == 'keyboard-ink':
        bsdf.inputs['Alpha'].default_value = 0
    if dynamic:
        bsdf.inputs['Emission Color'].default_value = (*spec['color'], 1)
        bsdf.inputs['Emission Strength'].default_value = .1
    materials[key] = mat
    return mat

static, dynamic = [], []
for part in parts:
    positions = np.array(part['positions']).reshape(-1, 3)
    positions = positions[:, [0, 2, 1]]
    positions[:, 1] *= -1
    mesh = bpy.data.meshes.new(part['name'])
    mesh.from_pydata(positions.tolist(), [], np.arange(len(positions)).reshape(-1, 3).tolist())
    mesh.update()
    obj = bpy.data.objects.new(part['name'], mesh)
    scene.collection.objects.link(obj)
    if part['name'] == 'window-glow':
        obj.visible_shadow = False
    spec = {**part['material'], 'name': 'ipad-cover-glass'} if part['name'] == 'ipad-cover-glass' else part['material']
    obj.data.materials.append(material(spec, part['dynamic']))
    if part['name'] == 'monitor-chassis':
        bevel = obj.modifiers.new('Machined bezel edges', 'BEVEL'); bevel.width = .0012; bevel.segments = 3
    if part['dynamic']:
        uv = mesh.uv_layers.new(name='UVMap')
        uv.data.foreach_set('uv', part['uv'])
        obj['dynamic'] = part['name']
        obj['label'] = part['label']
        dynamic.append(obj)
    else:
        mesh.uv_layers.new(name='UVMap')
        detail = mesh.uv_layers.new(name='DetailUV')
        detail.data.foreach_set('uv', part['uv'])
        if part.get('lightmapStrip'):
            # Projecting stacked folds onto a plane overlaps their lighting. Keep the
            # authored tube UVs in 24 short, separate strips before atlas packing.
            strip_uv = mesh.uv_layers.new(name='CableUV')
            source_uv = np.array(part['uv']).reshape(-1, 2)
            length, perimeter = part['lightmapStrip']['length'], part['lightmapStrip']['perimeter']
            for polygon in mesh.polygons:
                chart = min(23, int(math.floor(source_uv[polygon.loop_start:polygon.loop_start + polygon.loop_total, 0].min() * 24 + .00001)))
                for index in polygon.loop_indices:
                    u, v = source_uv[index]
                    assert -.00001 <= u * 24 - chart <= 1.00001, 'Cable face crosses a lightmap strip boundary'
                    strip_uv.data[index].uv = ((u - chart / 24) * length * .25, (v + chart * 2) * perimeter * .25)
        authored_normals = part['name'] in ['tessan-body', 'wall-outlet-plate']
        bm = bmesh.new(); bm.from_mesh(mesh)
        bmesh.ops.remove_doubles(bm, verts=list(bm.verts), dist=.000001)
        bmesh.ops.dissolve_limit(bm, angle_limit=.015, verts=list(bm.verts), edges=list(bm.edges), **({'delimit': {'UV'}} if part.get('lightmapStrip') else {}))
        bm.to_mesh(mesh); bm.free()
        mesh.set_sharp_from_angle(angle=math.radians(60))
        for polygon in mesh.polygons:
            polygon.use_smooth = True
        if authored_normals:
            # Opened casings retain the original smooth normal at their flat-panel seam.
            normals = np.array(part['normals']).reshape(-1, 3)[:, [0, 2, 1]]
            normals[:, 1] *= -1
            source_vertices = KDTree(len(positions))
            for index, position in enumerate(positions): source_vertices.insert(position, index)
            source_vertices.balance()
            restored_normals = []
            for vertex in mesh.vertices:
                _, index, distance = source_vertices.find(vertex.co)
                assert distance <= .000001, 'Opened casing vertex moved during simplification'
                restored_normals.append(normals[index].tolist())
            mesh.normals_split_custom_set_from_vertices(restored_normals)
            group = obj.vertex_groups.new(name='AuthoredNormals')
            group.add(list(range(len(mesh.vertices))), 1, 'REPLACE')
        static.append(obj)

if '--preview' in sys.argv:
    bpy.ops.mesh.primitive_plane_add(size=200, location=(0, 0, -.004))
    floor = bpy.context.object
    floor.data.materials.append(material({'name':'studio', 'color':[.59,.60,.59], 'roughness':.9, 'metalness':0}))
    scene.render.image_settings.file_format = 'PNG'
    scene.cycles.samples = 48
    for index, pose in enumerate(json.loads(BUILD.joinpath('cameras.json').read_text())):
        camera_data = bpy.data.cameras.new('Composition')
        camera = bpy.data.objects.new('Composition', camera_data); scene.collection.objects.link(camera)
        x, y, z = pose['position']; camera.location = (x, -z, y)
        x, y, z = pose['target']; target = Vector((x, -z, y))
        camera.rotation_euler = (target - camera.location).to_track_quat('-Z', 'Y').to_euler()
        camera_data.sensor_fit = 'VERTICAL'; camera_data.sensor_height = 24
        camera_data.lens = 12 / math.tan(math.radians(pose['fov'] / 2))
        scene.camera = camera
        scene.render.resolution_y = 1000
        scene.render.resolution_x = round(1000 * pose['aspect'])
        scene.render.resolution_percentage = 100
        scene.render.filepath = str(BUILD / f'composition-{index}.png')
        bpy.ops.render.render(write_still=True)
    print('PREVIEW_COMPLETE', flush=True)
    sys.exit(0)

# Keep desktop detail independent of room surfaces and the long under-desk wiring.
groups = [('desk', 4096, [obj for obj in static if not room_part(obj)])]
if has_room:
    groups.append(('room', 4096, [obj for obj in static if room_part(obj)]))
models, layout_metrics = [], {}
for name, size, objects in groups:
    assert objects, f'No objects found for {name} atlas'
    bpy.ops.object.select_all(action='DESELECT')
    for obj in objects: obj.select_set(True)
    bpy.context.view_layer.objects.active = objects[0]
    bpy.ops.object.join()
    model = bpy.context.object
    model.name = f'{name}-baked'
    model['atlas'] = name
    models.append(model)
    # Keep large faces flat and rounded edge highlights smooth.
    normal = model.modifiers.new('Area weighted normals', 'WEIGHTED_NORMAL')
    normal.keep_sharp = True
    authored_group = model.vertex_groups.get('AuthoredNormals')
    if authored_group:
        protected_vertices = {v.index for v in model.data.vertices if any(g.group == authored_group.index and g.weight > 0 for g in v.groups)}
        protected_loops = [loop.index for loop in model.data.loops if loop.vertex_index in protected_vertices]
        protected_normals = np.array([model.data.corner_normals[i].vector[:] for i in protected_loops])
        normal.vertex_group = 'AuthoredNormals'
        normal.invert_vertex_group = True
    bpy.ops.object.modifier_apply(modifier=normal.name)
    if authored_group:
        preserved_normals = np.array([model.data.corner_normals[i].vector[:] for i in protected_loops])
        assert np.allclose(protected_normals, preserved_normals, rtol=0, atol=.0003), 'Opened casing normals changed during weighted-normal processing'
    model.data.uv_layers.active_index = 0
    if room_only and name == 'desk':
        # Reuse the exact prior UVs, rather than relying on another identical pack.
        with bpy.data.libraries.load(str(BUILD / 'workstation.blend'), link=False) as (source, loaded):
            assert 'desk-baked' in source.objects, 'Previous desk mesh is missing'
            loaded.objects = ['desk-baked']
        previous = loaded.objects[0]
        for attribute, field, width, dtype in [('vertices', 'co', 3, np.float32), ('loops', 'vertex_index', 1, np.int32), ('polygons', 'loop_total', 1, np.int32)]:
            old = getattr(previous.data, attribute); new = getattr(model.data, attribute)
            assert len(old) == len(new), 'Desk geometry changed; run a full bake'
            old_values = np.empty(len(old) * width, dtype=dtype); new_values = np.empty_like(old_values)
            old.foreach_get(field, old_values); new.foreach_get(field, new_values)
            assert np.array_equal(old_values, new_values), 'Desk geometry changed; run a full bake'
        old_uv = np.empty(len(previous.data.loops) * 2, dtype=np.float32)
        previous.data.uv_layers[0].data.foreach_get('uv', old_uv)
        model.data.uv_layers[0].data.foreach_set('uv', old_uv)
        previous_mesh = previous.data
        bpy.data.objects.remove(previous); bpy.data.meshes.remove(previous_mesh)
        for library in list(bpy.data.libraries):
            if Path(bpy.path.abspath(library.filepath)).resolve() == (BUILD / 'workstation.blend').resolve():
                bpy.data.libraries.remove(library)
        print('Reusing verified desk geometry UVs and existing desk textures', flush=True)
    else:
        bpy.ops.object.mode_set(mode='EDIT')
        bpy.ops.mesh.select_all(action='SELECT')
        bpy.ops.uv.smart_project(angle_limit=math.radians(70), island_margin=.004, area_weight=.3, correct_aspect=False)
        if name == 'room' or model.data.uv_layers.get('CableUV'):
            # Small sockets need more texels than walls; otherwise their dark slots bleed into the casing.
            bm = bmesh.from_edit_mesh(model.data)
            layer = bm.loops.layers.uv.active
            cable_uv = bm.loops.layers.uv.get('CableUV')
            for face in bm.faces:
                if cable_uv and any(loop[cable_uv].uv.length_squared > 0 for loop in face.loops):
                    for loop in face.loops: loop[layer].uv = loop[cable_uv].uv
                surface = model.data.materials[face.material_index].name
                scale = 1 if name != 'room' else 8 if surface.startswith(('room-outlet-', 'room-tessan-')) or surface in ['desk-extension-plastic', 'desk-extension-cord'] else 3 if surface in ['desk-cable-strap', 'caldigit-cable-jacket'] else 1
                if scale != 1:
                    for loop in face.loops:
                        loop[layer].uv *= scale
            if cable_uv: bm.loops.layers.uv.remove(cable_uv)
            bmesh.update_edit_mesh(model.data)
        # Keep eight physical pixels of padding at each atlas resolution.
        bpy.ops.uv.pack_islands(rotate=True, rotate_method='CARDINAL', scale=True, margin_method='FRACTION', margin=8 / size, shape_method='CONVEX', merge_overlap=False)
        bpy.ops.object.mode_set(mode='OBJECT')
    model.data.calc_loop_triangles()
    uv = np.empty((len(model.data.loops), 2), dtype=np.float32)
    model.data.uv_layers[0].data.foreach_get('uv', uv.ravel())
    triangles = np.empty((len(model.data.loop_triangles), 3), dtype=np.int32)
    model.data.loop_triangles.foreach_get('loops', triangles.ravel())
    p = uv[triangles]
    uv_area = np.abs((p[:, 1, 0] - p[:, 0, 0]) * (p[:, 2, 1] - p[:, 0, 1]) - (p[:, 1, 1] - p[:, 0, 1]) * (p[:, 2, 0] - p[:, 0, 0])).sum() / 2
    print(f'{name}: {len(model.data.polygons)} polygons; {size}px atlas UV triangle area: {uv_area:.2%}', flush=True)
    assert .4 < uv_area <= 1 and np.isfinite(uv).all() and uv.min() >= 0 and uv.max() <= 1, f'{name} atlas packing lost detail or left the tile'
    layout_metrics[name] = {'size': size, 'padding_pixels': 8, 'uv_triangle_area': float(uv_area)}
    del uv, triangles, p
BUILD.joinpath('room-uv-layout.json').write_text(json.dumps(layout_metrics, indent=2) + '\n')
if '--layout-check' in sys.argv:
    bpy.ops.wm.save_as_mainfile(filepath=str(BUILD / 'room-layout-check.blend'))
    print('LAYOUT_CHECK_COMPLETE', flush=True)
    sys.exit(0)

# Room floorboards already receive contact shadows in their atlas.
if not has_room:
    bpy.ops.mesh.primitive_plane_add(size=4.8, location=(0, -.25, -.004))
    ground = bpy.context.object; ground.name = 'contact-shadow'
    ground.data.materials.append(material({'name':'floor', 'color':[.78,.78,.78], 'roughness':.9, 'metalness':0}))

def denoise_atlas(atlas, model, size, radiance):
    assert size == 4096 and tuple(atlas.size) == (size, size), 'Denoising requires the full 4K atlas'
    name = model['atlas']
    previous_scene, view_layer = bpy.context.scene, bpy.context.view_layer
    active, selected = view_layer.objects.active, list(bpy.context.selected_objects)
    samples = scene.cycles.samples
    settings = {key: getattr(scene.render.bake, key) for key in ['use_pass_direct', 'use_pass_indirect', 'use_pass_color', 'normal_space', 'margin']}
    targets, guides, emissions = [], [], []
    surface_mask = None
    composite = tree = camera = camera_data = result = None
    result_path = BUILD / f'{name}-denoisedImage.exr'
    result_path.unlink(missing_ok=True)
    try:
        scene.cycles.samples = 1
        scene.render.bake.use_pass_direct = scene.render.bake.use_pass_indirect = False
        scene.render.bake.use_pass_color = True
        scene.render.bake.normal_space = 'OBJECT'
        scene.render.bake.margin = 8
        bpy.ops.object.select_all(action='DESELECT'); model.select_set(True); view_layer.objects.active = model
        for mat in model.data.materials:
            nodes = mat.node_tree.nodes
            previous = nodes.active
            node = nodes.new('ShaderNodeTexImage'); nodes.active = node
            targets.append((nodes, node, previous))
        for guide_name, kind in [('albedo', 'DIFFUSE'), ('normal', 'NORMAL'), *([('surface', 'EMIT')] if name == 'desk' else [])]:
            guide = bpy.data.images.new(f'{name} denoise {guide_name}', width=size, height=size, alpha=False, float_buffer=True)
            guides.append(guide)
            for _, node, _ in targets: node.image = guide
            if kind == 'EMIT':
                scene.render.bake.margin = 0
                for mat in model.data.materials:
                    bsdf = mat.node_tree.nodes['Principled BSDF']
                    color, strength = bsdf.inputs['Emission Color'], bsdf.inputs['Emission Strength']
                    emissions.append((color, color.default_value[:], strength, strength.default_value))
                    color.default_value = (1, 1, 1, 1)
                    strength.default_value = 1 if mat.name in ['desk-powder-coat', 'ipad-cover-glass', 'ipad-aluminum', 'woven'] or mat.name.startswith('chair-') else 0
            print(f'Baking {name} denoise {guide_name} guide', flush=True)
            bpy.ops.object.bake(type=kind)
            if kind == 'EMIT':
                values = np.empty(len(guide.pixels), dtype=np.float32)
                guide.pixels.foreach_get(values)
                surface_mask = values.reshape(-1, 4)[:, 0] > .5
                assert surface_mask.any(), 'Desk paint, chair, and iPad surfaces are missing from the denoise guide'
                print(f'Denoising {int(surface_mask.sum())} desk paint, chair, and iPad surface texels', flush=True)
                del values
            if kind == 'NORMAL':
                values = np.empty(len(guide.pixels), dtype=np.float32)
                guide.pixels.foreach_get(values)
                values.reshape(-1, 4)[:, :3] = values.reshape(-1, 4)[:, :3] * 2 - 1
                guide.pixels.foreach_set(values); guide.update()
                del values
        # Filter lighting noise with albedo and normals retaining material detail.
        composite = bpy.data.scenes.new(f'{name} atlas denoise')
        composite.render.engine = 'BLENDER_WORKBENCH'
        composite.render.resolution_x = composite.render.resolution_y = size
        composite.render.resolution_percentage = 100
        composite.render.compositor_device = composite.render.compositor_denoise_device = 'CPU'
        composite.render.compositor_precision = 'FULL'
        tree = bpy.data.node_groups.new(f'{name} atlas denoise', 'CompositorNodeTree')
        composite.compositing_node_group = tree
        denoise = tree.nodes.new('CompositorNodeDenoise')
        denoise.inputs['HDR'].default_value = True
        denoise.inputs['Prefilter'].default_value = 'Accurate'
        for image, socket in zip([atlas, *guides[:2]], ['Image', 'Albedo', 'Normal']):
            node = tree.nodes.new('CompositorNodeImage'); node.image = image
            tree.links.new(node.outputs['Image'], denoise.inputs[socket])
        output = tree.nodes.new('CompositorNodeOutputFile')
        output.directory = str(BUILD); output.file_name = f'{name}-denoised'
        output.format.media_type = 'IMAGE'; output.format.file_format = 'OPEN_EXR'
        output.format.color_depth = '32'; output.format.color_mode = 'RGBA'; output.save_as_render = False
        output.file_output_items.new('RGBA', 'Image')
        tree.links.new(denoise.outputs['Image'], output.inputs['Image'])
        tree.interface.new_socket(name='Image', in_out='OUTPUT', socket_type='NodeSocketColor')
        group_output = tree.nodes.new('NodeGroupOutput')
        tree.links.new(denoise.outputs['Image'], group_output.inputs['Image'])
        camera_data = bpy.data.cameras.new(f'{name} denoise camera')
        camera = bpy.data.objects.new(f'{name} denoise camera', camera_data)
        composite.collection.objects.link(camera); composite.camera = camera
        print(f'Denoising {name} radiance with native OIDN', flush=True)
        bpy.ops.render.render(scene=composite.name)
        assert result_path.is_file() and result_path.stat().st_size > 0, 'Denoising did not produce a fresh EXR'
        result = bpy.data.images.load(str(result_path), check_existing=False)
        values = np.empty(len(result.pixels), dtype=np.float32)
        result.pixels.foreach_get(values)
        assert tuple(result.size) == (size, size) and values.size == size * size * 4 and np.isfinite(values).all(), 'Denoised atlas is incomplete or non-finite'
        assert values.reshape(-1, 4)[:, :3].max() > .1, 'Denoiser returned an empty atlas'
        if surface_mask is not None:
            # Filter paint, chair, and iPad surfaces; retain lighting gutters and tiny hardware lettering.
            values.reshape(-1, 4)[~surface_mask] = radiance.reshape(-1, 4)[~surface_mask]
        atlas.pixels.foreach_set(values); atlas.update()
        return values
    finally:
        for color, original_color, strength, original_strength in emissions:
            color.default_value = original_color; strength.default_value = original_strength
        scene.cycles.samples = samples
        for key, value in settings.items(): setattr(scene.render.bake, key, value)
        if bpy.context.window:
            bpy.context.window.scene = previous_scene; bpy.context.window.view_layer = view_layer
        with bpy.context.temp_override(scene=previous_scene, view_layer=view_layer):
            bpy.ops.object.select_all(action='DESELECT')
            for obj in selected: obj.select_set(True)
            view_layer.objects.active = active
        for nodes, node, previous in targets:
            nodes.remove(node); nodes.active = previous
        if composite is not None: bpy.data.scenes.remove(composite)
        if camera is not None: bpy.data.objects.remove(camera, do_unlink=True)
        if camera_data is not None: bpy.data.cameras.remove(camera_data)
        if tree is not None: bpy.data.node_groups.remove(tree)
        for image in [*guides, *([result] if result is not None else [])]: bpy.data.images.remove(image)


scene.render.bake.use_pass_direct = True
scene.render.bake.use_pass_indirect = True
scene.render.bake.use_pass_color = True
for model, (name, size, _) in zip(models, groups):
    if room_only and name == 'desk':
        continue
    atlas = bpy.data.images.new(f'{name}-daylight', width=size, height=size, alpha=False, float_buffer=True)
    for mat in model.data.materials:
        node = mat.node_tree.nodes.new('ShaderNodeTexImage'); node.image = atlas
        mat.node_tree.nodes.active = node
    bpy.ops.object.select_all(action='DESELECT'); model.select_set(True); bpy.context.view_layer.objects.active = model
    scene.render.bake.margin = 8
    print(f'Baking {name} daylight atlas', flush=True)
    bpy.ops.object.bake(type='DIFFUSE')
    radiance = np.empty(len(atlas.pixels), dtype=np.float32)
    atlas.pixels.foreach_get(radiance)
    print(f'{name} raw peak radiance: {radiance.reshape(-1, 4)[:, :3].max():.3f}', flush=True)
    if name == 'room':
        # DIFFUSE receives illumination but excludes the window's visible emission.
        emission = bpy.data.images.new('room-emission', width=size, height=size, alpha=False, float_buffer=True)
        for mat in model.data.materials:
            node = mat.node_tree.nodes.new('ShaderNodeTexImage'); node.image = emission
            mat.node_tree.nodes.active = node
        print('Baking visible window emission', flush=True)
        bpy.ops.object.bake(type='EMIT')
        emission_pixels = np.empty(len(emission.pixels), dtype=np.float32)
        emission.pixels.foreach_get(emission_pixels)
        radiance.reshape(-1, 4)[:, :3] += emission_pixels.reshape(-1, 4)[:, :3]
        atlas.pixels.foreach_set(radiance); atlas.update()
        del emission_pixels
    radiance = denoise_atlas(atlas, model, size, radiance)
    peak = radiance.reshape(-1, 4)[:, :3].max()
    encoding_range = 32 if name == 'room' else 4
    print(f'{name} peak baked radiance: {peak:.3f} / {encoding_range}', flush=True)
    if not np.isfinite(peak) or peak > encoding_range:
        np.save(BUILD / f'{name}-radiance-overflow.npy', radiance)
    assert np.isfinite(peak) and peak <= encoding_range, 'Increase encoding range and browser decoding together'
    # Both files preserve scene-linear radiance; the browser applies AgX once.
    scene.view_settings.view_transform = 'Standard'
    if name == 'room':
        rgb = radiance.reshape(-1, 4)[:, :3]
        multiplier = np.ceil(np.clip(rgb.max(axis=1) / encoding_range, 1 / 255, 1) * 255) / 255
        packed = np.empty_like(radiance).reshape(-1, 4)
        packed[:, :3] = np.clip(rgb / (multiplier[:, None] * encoding_range), 0, 1)
        packed[:, 3] = multiplier
        rgbm = bpy.data.images.new('room-daylight-rgbm', width=size, height=size, alpha=True, float_buffer=True)
        # Blender's float render buffer is associated-alpha even for CHANNEL_PACKED.
        # Premultiply only this intermediate buffer; save_render writes straight PNG RGB.
        packed[:, :3] *= multiplier[:, None]
        rgbm.alpha_mode = 'PREMUL'
        rgbm.pixels.foreach_set(packed.ravel()); rgbm.update()
        scene.render.image_settings.file_format = 'PNG'; scene.render.image_settings.color_mode = 'RGBA'
        scene.render.image_settings.color_depth = '8'
        scene.view_settings.exposure = 0
        rgbm.save_render(str(BUILD / 'room-daylight.png'), scene=scene)
        subprocess.run(['/opt/homebrew/bin/cwebp', '-lossless', '-q', '100', '-m', '6', '-exact', str(BUILD / 'room-daylight.png'), '-o', str(OUT / 'room-daylight.webp')], check=True)
        del rgb, multiplier, packed
    else:
        scene.render.image_settings.file_format = 'JPEG'; scene.render.image_settings.quality = 95
        scene.view_settings.exposure = -2
        atlas.save_render(str(OUT / 'desk-daylight.jpg'), scene=scene)
    del radiance
    scene.view_settings.exposure = 0
    occlusion = bpy.data.images.new(f'{name}-occlusion', width=size // 2, height=size // 2, alpha=False)
    for mat in model.data.materials:
        node = mat.node_tree.nodes.new('ShaderNodeTexImage'); node.image = occlusion
        mat.node_tree.nodes.active = node
    print(f'Baking {name} material contact occlusion', flush=True)
    scene.render.bake.margin = 4  # Match the daylight padding in normalized coordinates.
    bpy.ops.object.bake(type='AO')
    scene.render.image_settings.file_format = 'JPEG'; scene.render.image_settings.color_mode = 'RGB'
    scene.render.image_settings.quality = 95
    occlusion.save_render(str(OUT / f'{name}-occlusion.jpg'), scene=scene)
    scene.view_settings.view_transform = 'AgX'


if not has_room:
    shadow = bpy.data.images.new('desk-contact', width=1024, height=1024, alpha=True)
    node = ground.data.materials[0].node_tree.nodes.new('ShaderNodeTexImage'); node.image = shadow
    ground.data.materials[0].node_tree.nodes.active = node
    bpy.ops.object.select_all(action='DESELECT'); ground.select_set(True); bpy.context.view_layer.objects.active = ground
    scene.cycles.samples = 256
    print('Baking contact shadows', flush=True)
    bpy.ops.object.bake(type='DIFFUSE')
    pixels = np.array(shadow.pixels[:], dtype=np.float32).reshape(-1, 4)
    luma = pixels[:, :3].mean(axis=1)
    # Divide by the unoccluded lighting at each pixel, so the desk retains its full shadow.
    for obj in [*models, *dynamic]: obj.hide_render = True
    print('Baking unoccluded floor', flush=True)
    bpy.ops.object.bake(type='DIFFUSE')
    background = np.array(shadow.pixels[:], dtype=np.float32).reshape(-1, 4)[:, :3].mean(axis=1)
    for obj in [*models, *dynamic]: obj.hide_render = False
    alpha = np.clip(1 - luma / np.maximum(background, .001), 0, .68)
    x, y = np.meshgrid(np.linspace(-1, 1, 1024), np.linspace(-1, 1, 1024))
    alpha *= np.clip((1 - np.maximum(abs(x), abs(y))) * 8, 0, 1).ravel()
    # Smooth Monte Carlo noise only in the shadow mask, keeping the material atlas sharp.
    alpha = alpha.reshape(1024, 1024)
    weights = np.array([1, 4, 6, 4, 1]) / 16
    for axis in (0, 1):
        alpha = np.apply_along_axis(lambda row: np.convolve(np.pad(row, 2, mode='edge'), weights, mode='valid'), axis, alpha)
    pixels[:, :3] = (.13, .115, .105); pixels[:, 3] = alpha.ravel()
    shadow.pixels.foreach_set(pixels.ravel())
    shadow.update()
    shadow.filepath_raw = str(OUT / 'desk-contact.png'); shadow.file_format = 'PNG'; shadow.save()

# Retain the editable scene, lighting, and bake UVs outside the published output.
bpy.ops.wm.save_as_mainfile(filepath=str(BUILD / 'workstation.blend'))

# Export the UV layout and geometry; the browser supplies baked and live materials.
# Keep distinct physical properties for the browser's view-dependent reflections.
for model in models:
    for index, source in enumerate(list(model.data.materials)):
        bsdf = source.node_tree.nodes.get('Principled BSDF')
        mat = bpy.data.materials.new(f'{source.name}-baked')
        mat.use_nodes = True
        target = mat.node_tree.nodes.get('Principled BSDF')
        for name in ['Base Color', 'Roughness', 'Metallic']:
            target.inputs[name].default_value = bsdf.inputs[name].default_value
        mat.use_backface_culling = source.name not in ['woven', 'bed-linen', 'room-curtain']
        model.data.materials[index] = mat
bpy.ops.object.select_all(action='DESELECT')
for obj in [*models, *dynamic]: obj.select_set(True)
bpy.context.view_layer.objects.active = models[0]
bpy.ops.export_scene.gltf(filepath=str(OUT / 'workstation.glb'), export_format='GLB', use_selection=True, export_extras=True, export_materials='EXPORT')
OUT.joinpath('source.sha256').write_text(BUILD.joinpath('source.sha256').read_text())
print('BAKE_COMPLETE', flush=True)
