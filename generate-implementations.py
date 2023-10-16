#!/usr/bin/env python3
"""Generates the implementations based on ``implementations.yaml``"""

import yaml
import os
import jinja2
import re
import shutil


DEFAULT_X86_AES_GUARD = 'target_arch == "x86_64" && aes_enabled'
DEFAULT_X86_AVX2_GUARD = 'target_arch == "x86_64" && avx2_enabled'
DEFAULT_AARCH64_NEON_GUARD = 'target_arch == "aarch64" && neon_enabled'


def read_yaml():
    with open('implementations.yaml', 'r') as f:
        return yaml.safe_load(f)


def read_scheme_metadata(type, scheme_name):
    metadata_path = os.path.join(
        'pqclean', f'crypto_{type}', scheme_name, 'META.yml')
    with open(metadata_path) as f:
        metadata = yaml.safe_load(f)

    return metadata


def nameize(value):
    return re.sub(r'[^a-zA-Z0-9]', '', value).lower()


def render_template(target_dir, target_file, template_file, **templ_vars):
    def namespaceize(value):
        return re.sub(r'(\s|[-_])', '', value).upper()

    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader('pqcrypto-template'),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters['namespaceize'] = namespaceize
    env.filters['nameize'] = nameize
    env.filters['split'] = lambda x, y: x.split(y)

    target_path = os.path.join(target_dir, target_file)
    template = env.get_template(template_file)
    template.stream(**templ_vars).dump(target_path)


def generate_scheme(name, type, properties):
    """Schemes: list of dicts from yaml"""
    target_dir = f"pqcrypto-{name}"
    src_dir = os.path.join(target_dir, "src")
    try:
        shutil.rmtree(target_dir)
    except FileNotFoundError:
        pass
    os.makedirs(src_dir)
    try:
        os.symlink(os.path.join('..', 'pqclean'),
                   os.path.join(target_dir, 'pqclean'),
                   target_is_directory=True)
    except FileExistsError:
        pass

    render_template(
        target_dir, 'Cargo.toml', 'scheme/Cargo.toml.j2',
        traits_version=implementations['traits_version'],
        # internals_version=implementations['internals_version'],
        name=name,
        type=type,
        insecure=properties.get('insecure', False),
        version=properties['version'],
        implementations=properties['implementations'],
    )

    render_template(
        target_dir, 'build.rs', 'scheme/build.rs.j2',
        name=name,
        type=type,
        implementations=properties['implementations'],
        schemes=properties['schemes'],
        x86_aes_guard=properties.get('x86_aes_guard', DEFAULT_X86_AES_GUARD),
        x86_avx2_guard=properties.get('x86_avx2_guard', DEFAULT_X86_AVX2_GUARD),
        aarch64_neon_guard=properties.get('aarch64_neon_guard', DEFAULT_AARCH64_NEON_GUARD),
    )

    metadatas = dict()
    for scheme in properties['schemes']:
        metadatas[scheme['name']] = read_scheme_metadata(type, scheme['name'])

    render_template(
        target_dir, 'src/ffi.rs', 'scheme/src/ffi.rs.j2',
        insecure=properties.get('insecure', False),
        type=type,
        name=name,
        metadatas=metadatas,
        schemes=properties['schemes'],
    )

    for scheme in properties['schemes']:
        render_template(
            target_dir, f"src/{ nameize(scheme['name']) }.rs",
            "scheme/src/scheme.rs.j2",
            type=type,
            name=name,
            insecure=properties.get('insecure', False),
            scheme=scheme,
        )

    render_template(
        target_dir, 'src/lib.rs', 'scheme/src/lib.rs.j2',
        name=name,
        type=type,
        insecure=properties.get('insecure', False),
        notes=properties.get('notes', None),
        schemes=properties['schemes'],
    )

    render_template(
        target_dir, 'README.md', 'scheme/README.md.j2',
        name=name,
        type=type,
        insecure=properties.get('insecure', False),
        notes=properties.get('notes', None),
        schemes=properties['schemes'],
    )


def generate_pqcrypto_crate(implementations):
    version = implementations['pqcrypto_version']
    target_dir = 'pqcrypto'
    shutil.rmtree(target_dir)
    os.makedirs(os.path.join(target_dir, 'src'))
    any_insecure = any(kem.get('insecure') for (_name, kem) in implementations['kems'].items())
    any_insecure |= any(sig.get('insecure') for (_name, sig) in implementations['signs'].items())

    render_template(
        target_dir, 'Cargo.toml', "pqcrypto/Cargo.toml.j2",
        version=version,
        traits_version=implementations['traits_version'],
        kems=implementations['kems'],
        signs=implementations['signs'],
    )
    render_template(
        target_dir, 'src/lib.rs', 'pqcrypto/src/lib.rs.j2',
        kems=implementations['kems'],
        signs=implementations['signs'],
    )
    render_template(
        target_dir, 'README.md', 'pqcrypto/README.md.j2',
        kems=implementations['kems'],
        signs=implementations['signs'],
        any_insecure=any_insecure,
    )
    shutil.copytree(
        "pqcrypto-template/pqcrypto/examples",
        os.path.join(target_dir, "examples")
    )


def generate_cargo_workspace(implementations):
    names = []
    for name in implementations['kems'].keys():
        names.append(f'pqcrypto-{name}')
    for name in implementations['signs'].keys():
        names.append(f'pqcrypto-{name}')

    render_template(
        '.', 'Cargo.toml', 'workspace-Cargo.toml.j2',
        names=names
    )


if __name__ == "__main__":
    implementations = read_yaml()
    for (name, properties) in implementations['kems'].items():
        generate_scheme(name, 'kem', properties)
    for (name, properties) in implementations['signs'].items():
        generate_scheme(name, 'sign', properties)

    generate_cargo_workspace(implementations)
    generate_pqcrypto_crate(implementations)
    os.system("cargo fmt")
