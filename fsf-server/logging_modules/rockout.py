#! /usr/bin/env python
#
"""
@author: Adam Kniffen
@contact: adamkniffen@gmail.com
@copyright: Copyright 2017
@organization: MOCYBER
@status: Development
"""
import json
import hashlib
import sys


def template(job, objectid, generated_by, parent=False):
    """
    return the dict template for an object
    :param job: type(str), the scan job
    :param objectid: type(str) the objectID of the new object you're creating
    :param generated_by: type(str), the FSF module that producted the object
    :param parent: (OPTIONAL) type(str), the parent objectid or False to return an empty string
    :return: object dict
    """
    if parent is False:
        parent = ""
    doc = {
            "meta": {
                "parentid": parent,
                "job": job,
                "objectid": objectid,
                "generated_by": generated_by
            },
    }
    return doc


def objectid(salt, scanid):
    """
    return a md5 UID. Note, be careful with the salt value, if you dig too far into the scan dict you might find that
    keys you expected aren't there
    :param salt:
    :param scanid:
    :return:
    """
    return hashlib.md5("%s%s" % (salt, scanid)).hexdigest()


def walk(d, job, parent, generated_by):
    """
    walk a FSF scan dict where the clue to recurse is "EXTRACT_", and whenever we recurse we need to provide a parentID
    module name
    :param d: the dictionary
    :param job: the scan job
    :param parent: the object parent
    :param generated_by: the EXTRACT module or submission event that spawned object mining
    :return: Generator
    """

    # we've got objects, so for each we need to recurse...
    parent = parent
    for ob in d:

        if "META_" in ob:
            continue

        # keep moving if this happens (shouldn't ever happen?)!
        if "EXTRACT_" in ob:
            for res in walk(d=d[ob], job=job, parent=parent, generated_by=ob):
                yield res

        if "Object" in ob:
            obj = template(parent=parent, job=job, objectid=objectid(salt=d[ob], scanid=job),
                           generated_by=generated_by)

        # we can't leave this hanging, so execute each mining task in its own for loop
            for module in d[ob]:
                # mine all the meta, ignore any extracted subobjects, yield the goodies
                if "EXTRACT_" not in module:
                    obj[module] = d[ob][module]
            yield obj

            for module in d[ob]:
                if "EXTRACT_" in module:
                    # we've got file babies, so its time to assign parentage
                    parent = obj['meta']['objectid']
                    for res in walk(d=d[ob][module], job=job, parent=parent, generated_by=module):
                        yield res


def rockout(d):
    objs = []

    # generate the root object
    job = "scan-%s" % hashlib.md5("%s-%s" % (d["Scan Time"], d["Filename"])).hexdigest()
    rootdoc = template(job=job, objectid=objectid(salt=d.items(), scanid=job), generated_by="submission")
    count = 0
    for key in d:

        if key != "Object":
            rootdoc[key] = d[key]

    # now process "The Object..." it has to be there as it was the file that was submitted to FSF

    obj = template(parent=False, job=job, objectid=objectid(salt=d["Object"].items(), scanid=job),
                   generated_by="submission")
    for module in d["Object"]:
        if "EXTRACT_" not in module:
            obj[module] = d["Object"][module]
    objs.append(obj)

    for module in d["Object"]:
        if "EXTRACT_" in module:
        # we have extraction, so start the walkin'

            for res in walk(d=d["Object"][module], parent=obj['meta']['objectid'], job=job, generated_by=module):
                objs.append(res)

    rootdoc["objects"] = objs
    return rootdoc

if __name__ == "__main__":
    print rockout(d=sys.stdin())
