from os import path

try:
    import git
    _REPO = git.Repo(path=__file__, search_parent_directories=True)

    try:
        VERSION = _REPO.git.symbolic_ref('HEAD', short=True)
    except GitCommandError:
        VERSION = _REPO.git.show(format='format:%h', no_patch=True)

except:
    _VERSION_FILE = path.join(
        path.dirname(path.realpath(__file__)),
        path.pardir,
        path.pardir,
        'VERSION'
    )

    with open(_VERSION_FILE) as v:
        VERSION = v.read()


if __name__ == '__main__':
    print(VERSION)
