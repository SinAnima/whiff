{
	"patcher" : {
		"fileversion" : 1,
		"appversion" : { "major" : 8, "minor" : 6, "revision" : 0 },
		"boxes" : [
			{ "box" : { "id" : "obj-1", "maxclass" : "newobj", "text" : "cycle~ 0.1" } },
			{ "box" : { "id" : "obj-2", "maxclass" : "ezdac~" } },
			{ "box" : { "id" : "obj-3", "maxclass" : "comment", "text" : "tide drone" } }
		],
		"lines" : [
			{ "patchline" : { "source" : [ "obj-1", 0 ], "destination" : [ "obj-2", 0 ] } }
		]
	}
}
