# -*- coding: utf-8 -*-
"""only analyze houdini"""

from rayvision_houdini.analyze_houdini import AnalyzeHoudini

analyze_info = {
    "cg_file": r"D:\houdini\CG file\flip_test_slice4.hip",
    "workspace": "c:/workspace",
    "software_version": "17.5.293",
    "project_name": "Project1",
    "custom_db_path": r"D:\test\upload",
    "plugin_config": {
        'renderman': '22.6'
    }
}

AnalyzeHoudini(**analyze_info).analyse()