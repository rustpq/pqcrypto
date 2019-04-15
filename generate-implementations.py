"""Generates the implementations based on ``implementations.yaml``"""

import yaml
import os
import jinja2
import re
import shutil


def read_yaml():
    with open('implementations.yaml', 'r') as f:
        return yaml.load(f)


def read_scheme_metadata(type, scheme_name):
    metadata_path = os.path.join(
        'pqclean', f'crypto_{type}', scheme_name, 'META.yml')
    with open(metadata_path) as f:
        metadata = yaml.load(f)

    return metadata


def render_template(target_dir, target_file, template_file, **templ_vars):
    def namespaceize(value):
        return re.sub(r'(\s|[-_])', '', value).upper()

    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader('pqcrypto-template'),
        undefined=jinja2.StrictUndefined,
    )
    env.filters['namespaceize'] = namespaceize
    env.filters['split'] = lambda x, y: x.split(y)

    target_path = os.path.join(target_dir, target_file)
    template = env.get_template(template_file)
    template.stream(**templ_vars).dump(target_path)


def generate_scheme(name, type, properties):
    """Schemes: list of dicts from yaml"""
    target_dir = f"pqcrypto-{name}"
    src_dir = os.path.join(target_dir, "src")
    shutil.rmtree(target_dir)
    os.makedirs(src_dir)
    try:
        os.symlink(os.path.join('..', 'pqclean'),
                   os.path.join(target_dir, 'pqclean'),
                   target_is_directory=True)
    except FileExistsError:
        pass

    render_template(
        target_dir, 'Cargo.toml', 'scheme/Cargo.toml.j2',
        name=name,
        type=type,
        version=properties['version'],
    )

    render_template(
        target_dir, 'build.rs', 'scheme/build.rs.j2',
        name=name,
        type=type,
        schemes=properties['schemes'],
    )

    metadatas = dict()
    for scheme in properties['schemes']:
        metadatas[scheme['name']] = read_scheme_metadata(type, scheme['name'])

    render_template(
        target_dir, 'src/ffi.rs', 'scheme/src/ffi.rs.j2',
        name=name,
        metadatas=metadatas,
        schemes=properties['schemes']
    )

    for scheme in properties['schemes']:
        render_template(
            target_dir, f"src/{ scheme['name'] }.rs",
            "scheme/src/scheme.rs.j2",
            name=name,
            scheme=scheme,
        )

    render_template(
        target_dir, 'src/lib.rs', 'scheme/src/lib.rs.j2',
        name=name,
        notes=properties.get('notes', None),
        schemes=properties['schemes'],
    )


def generate_pqcrypto_crate(implementations):
    from packaging import version
    version = max([version.parse(crate['version'])
                   for crate in implementations['kems'].values()])
    target_dir = 'pqcrypto'
    shutil.rmtree(target_dir)
    os.makedirs(os.path.join(target_dir, 'src'))

    render_template(
        target_dir, 'Cargo.toml', "pqcrypto/Cargo.toml.j2",
        version=version,
        kems=implementations['kems'],
    )
    render_template(
        target_dir, 'src/lib.rs', 'pqcrypto/src/lib.rs.j2',
        kems=implementations['kems'],
    )


def generate_cargo_workspace(implementations):
    names = []
    for name in implementations['kems'].keys():
        names.append(f'pqcrypto-{name}')

    render_template(
        '.', 'Cargo.toml', 'workspace-Cargo.toml.j2',
        names=names
    )


if __name__ == "__main__":
    implementations = read_yaml()
    for (name, properties) in implementations['kems'].items():
        generate_scheme(name, 'kem', properties)

    generate_cargo_workspace(implementations)
    generate_pqcrypto_crate(implementations)
