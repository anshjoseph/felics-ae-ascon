from os import path
from sys import argv


try:
    import git
    _REPO = git.Repo(path=__file__, search_parent_directories=True)
except:
    _REPO = None


def version():
    if _REPO is None:
        version_file = path.join(
            path.dirname(path.realpath(__file__)),
            path.pardir,
            path.pardir,
            'VERSION'
        )

        with open(version_file) as v:
            return v.read()

    prefix = 'felics-ae-v'
    version = _REPO.git.describe(match=prefix+'*', always=True)
    return version.replace(prefix, '')


def branch():
    if _REPO is None:
        return None

    try:
        return _REPO.git.symbolic_ref('HEAD', short=True)
    except git.GitCommandError:
        return 'DETACHED'


def commit():
    if _REPO is None:
        return None

    return _REPO.git.show(format='format:%h', no_patch=True)


def _main(arguments):
    template = '{version}' 
    if arguments:
       template = arguments[0]

    info = {
        'commit': commit(),
        'branch': branch(),
        'version': version()
    }
    
    print(template.format_map(info))


if __name__ == '__main__':
    _main(argv[1:])
