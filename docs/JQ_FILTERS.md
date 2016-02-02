Jq Filter Integration
=====================

Purpose
-------

Examining FSF output can be quite cumbersome due to how rich some of the output can be. Additionally, there are also scenarios where an analyst might wish to capture a unique relationship between an object and a sub-object that FSF exposes. For example, you might think it interesting that an executable with high entropy (as measured by a Yara signature) came from a rar or a zip file? Unfortunately, capturing these observations is a bit of a chicken and egg problem. How can one know the relationships between files and various meta data elements until they have been fully processed? 

To overcome this gap, the post-processing engine was added. Much like one would use Yara to capture observations on a file, the post-processor uses a similar approach, but instead of using Yara, uses jq. Jq is a mature, and very powerful JSON interpreter and may be extended to capture unique observations on FSF data. You can even develop detections based on relationships seen within FSF JSON output! In this paradigm, we can think of jq filters as jq signatures. 

Interested? Read on for more on how post-processing has been implemented.

Fundamentals
------------

As with everything in FSF; it's all about exposing intelligence. In the post-processing paradigm, we can expose intelligence concerning relationships from one file to another or one metadata attribute to another. Certain relationships are more noteworthy than others. Some are worth capturing but not alerting on, others might drive such a detection!

Use Cases
---------

Why would someone want to write jq filters on FSF output? Here are some use cases you might find interesting...

* The presence of certain filetypes within a file; such as, an scr/exe within a zip, rar, Office document, etc...
* When the compile time for an executable is within a certain time frame, say < 24 hours old.
* When a number of _suspicious_ macros exceeds a certain threshold.

In FSF, these observations are captured in a summary dictionary. Below is a brief snippet of multiple jq filters triggering different conditions from a large report.

```
 "Observations": [
    "An executable was found inside a ZIP file.",
    "An embedded file contained a self-extracting RAR that itself contained an executable payload.",
    "More than 10 unique objects were observed in this file.",
    "There were no matches found when VirusTotal was queried.",
    "More than 10 unique Yara signatures fired when processing this file!"
 ]
```

Implementation
--------------

Jq filters designed to analyze FSF data __MUST__ return a boolean result. Testing whether or not one will work is as simple as piping FSF output to the jq interpreter. Once you are confident in your approach, simply do the following.

* Add your jq script to the _jq_ directory within the fsf-server folder.
* Add an tuple entry to the _disposition.py_ list entitled _post_processor_.
** First element is your jq signature name.
** Second is the observation you want to capture.
** Last is whether or not you want to set the alert flag based on the observation. 

The following is an example of what this would look like within the ''disposition.py'' file:

```
 # STRUCTURE: List of tuples such that...
 #  Types:      [('string', 'string', boolean'), ...]
 #  Variables:  [('jq script', 'observation' , 'is archivable'), ...]
 
 post_processor = [('one_module.jq', 'Only one kind of module was run on for this report.', False),
                   ('no_yara_hits.jq', 'There doesn\'t appear to be any Yara signature hits for this scan.', False),
```
