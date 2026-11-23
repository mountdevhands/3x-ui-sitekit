"""Original editorial material for additional generated-site themes.

No real person, company, client, contact address, or professional credential is
claimed. The entries are short reading notes and observation exercises.
"""


def _article(slug, category, titles, summary, paragraphs):
    return {"slug": slug, "category": category, "titles": titles,
            "summary": summary, "paragraphs": paragraphs}


EXTRA_SITE_CONTENT = {
    "typography": {
        "names": ("Letterform Notes", "Quiet Type", "Between the Letters", "The Reading Measure"),
        "descriptions": (
            "Observations on letterforms, spacing, and the structure of readable pages.",
            "A small collection of type specimens and notes about the rhythm of text.",
            "Looking closely at the details that give a page its voice and pace.",
        ),
        "eyebrow": "Letters & reading",
        "about": (
            "This notebook considers typography through ordinary reading: a heading, a paragraph, a caption, and the spaces that connect them. Each note focuses on a detail that can be compared on a single page.",
            "The exercises use short passages and simple specimens. Keep the text consistent while changing one decision, and describe the difference in terms of what becomes easier to notice or follow.",
        ),
        "caption": "A study in strokes, counters, and the intervals between repeated forms.",
        "palettes": {
            "type-ivory": ("#F5F0E7", "#252321", "#6F6861", "#A34332", "#EAE1D3", "#D6CABC"),
            "type-slate": ("#EEF1F1", "#202C35", "#626F76", "#365F78", "#DCE5E8", "#C8D5DB"),
            "type-plum": ("#F3EDF0", "#372A35", "#786A74", "#7B4366", "#E8DBE3", "#D7C6D1"),
        },
        "articles": (
            _article("reading-measure", "Reading", ("Finding a comfortable measure", "A paragraph at three widths"),
                     "Compare the same paragraph in narrow, medium, and wide columns.", (
                         "Choose a paragraph that can be read without needing its surrounding article. Set it in three column widths while keeping the type size and line spacing unchanged.",
                         "Read each version at an ordinary pace. Notice where your eye returns to the beginning of a line, and whether a short final line interrupts the paragraph's shape.",
                         "Keep the version that suits the page's purpose. A caption, a long essay, and a narrow sidebar can each benefit from a different measure.",
                     )),
            _article("letter-pairs", "Spacing", ("Look at the space between pairs", "An exercise in optical spacing"),
                     "Repeated words make small differences between letter pairs easier to see.", (
                         "Write a short heading with several round, straight, and diagonal letters. Compare the spaces around those shapes before adjusting the word as a whole.",
                         "A useful specimen contains the same word on several lines. Change one pair at a time, then step back and read the heading without concentrating on the individual letters.",
                         "Save the earlier version beside the adjusted one. The comparison is more informative than trying to remember how the original spacing felt.",
                     )),
            _article("small-hierarchy", "Structure", ("A hierarchy with three levels", "Give each level a clear role"),
                     "A title, a subheading, and body text can carry a complete short page.", (
                         "Begin with the content outline. Decide which words introduce the whole page, which divide it into sections, and which belong to the continuous reading text.",
                         "Give each level a consistent treatment. Size, weight, spacing, and position offer several ways to make the structure visible without adding an extra style to every paragraph.",
                         "Review the page as a silhouette before reading it closely. The largest elements should help a reader predict the sequence and find a useful place to begin.",
                     )),
            _article("numeral-specimens", "Specimens", ("Keep a small numeral specimen", "Numbers deserve their own proof"),
                     "Dates, prices, and measurements reveal details that an alphabet specimen can miss.", (
                         "Make a specimen with a date, a short table, a decimal measurement, and a numbered list. Use the same examples whenever you compare a new typeface.",
                         "Look at the width and alignment of the digits. In a table, the relationship between columns matters alongside the shape of each individual numeral.",
                         "Include punctuation and symbols that the actual document needs. A short practical specimen is easier to judge than a page filled with unrelated characters.",
                     )),
            _article("quiet-captions", "Details", ("Writing a useful caption", "Small text with a clear purpose"),
                     "A caption should connect an image to the surrounding page.", (
                         "Start by identifying the detail that the reader should notice. Write a sentence that adds context to the image instead of repeating the nearest heading.",
                         "Set the caption beside the image and examine their spacing together. The distance should make their relationship clear even when several illustrations appear on one page.",
                         "Read the smallest text at its intended display size. Adjust the words as well as the typography when a caption becomes crowded or difficult to scan.",
                     )),
            _article("specimen-notebook", "Practice", ("Build a repeatable type specimen", "Keep the test text familiar"),
                     "A consistent set of sample text helps separate preference from habit.", (
                         "Choose a heading, a paragraph, a list, and a short quotation. Keep their wording fixed so that successive specimens can be compared directly.",
                         "Record the typeface, size, line spacing, and width beside each version. Add a brief observation about the reading experience while the comparison is still fresh.",
                         "Return to the specimen after working on other pages. The choices that continue to feel useful are good candidates for a small, dependable type system.",
                     )),
        ),
    },
    "cartography": {
        "names": ("Contour Notebook", "Ways on Paper", "Small Map Studies", "Lines of Place"),
        "descriptions": (
            "Notes about maps, landmarks, and the choices that make a place legible.",
            "A collection of small mapping exercises, route sketches, and visual keys.",
            "Exploring how lines, labels, and symbols describe a familiar landscape.",
        ),
        "eyebrow": "Maps & places",
        "about": (
            "A map begins with a question about a place. These notes examine the choices behind a route sketch, a legend, a group of labels, or a page of contour lines.",
            "The exercises are intended for observation and design. Keep sources and dates beside a working map, and use an appropriate current map when a real journey requires dependable navigation.",
        ),
        "caption": "An imagined terrain drawn as layered contours and a small network of paths.",
        "palettes": {
            "map-parchment": ("#F2EEDF", "#303C32", "#6B7565", "#617649", "#E1E5D0", "#CBD3BC"),
            "map-blueprint": ("#EAF0F5", "#25374A", "#657A8C", "#426F95", "#D7E3EC", "#BDCFE0"),
            "map-clay": ("#F4EDE6", "#43342C", "#857263", "#A46B45", "#EBDCCE", "#D9C4B2"),
        },
        "articles": (
            _article("map-question", "Purpose", ("Begin with one mapping question", "What should this map explain?"),
                     "A clear question makes the selection of features much easier.", (
                         "Choose a small area and write one question about it. You might want to compare entrances, show a walking route, or explain the relationship between several public spaces.",
                         "List the features that help answer that question. Draw a first version using only those features, then add context where the sketch becomes difficult to understand.",
                         "Ask someone to describe what they think the map shows. Their first reading can reveal whether the most prominent marks support the intended purpose.",
                     )),
            _article("working-legend", "Symbols", ("Make the legend while drawing", "A key that matches the marks"),
                     "Keep a small key beside a map as its visual language develops.", (
                         "Create one sample of every line, fill, and point symbol used in the drawing. Give each a short label while its meaning is still clear.",
                         "Compare similar symbols at the final page size. A difference that is obvious while zoomed in may become difficult to see in a compact legend.",
                         "Remove unused entries before sharing the map. The legend should describe the marks that appear on that particular sheet.",
                     )),
            _article("landmark-route", "Routes", ("Sketch a route through landmarks", "A familiar walk from memory"),
                     "Landmarks provide useful reference points for a first route sketch.", (
                         "Draw a familiar short route from memory and mark the places where you usually make a decision. Add the landmarks that help distinguish those points.",
                         "Compare the sketch with a dependable map or a later observation. Note where memory compressed a distance, omitted a turn, or exaggerated a memorable feature.",
                         "Keep both drawings. Their differences show which details carried the route in memory and which details needed a more careful record.",
                     )),
            _article("label-placement", "Labels", ("Give labels a place to breathe", "Read the map through its names"),
                     "Labels should help a reader connect a name with the correct feature.", (
                         "Place the most important names first. Leave enough room around each one to distinguish it from neighbouring lines, symbols, and other labels.",
                         "Read the sheet in small sections. Check that a label cannot easily be mistaken for the name of an adjacent street, boundary, or point.",
                         "Use consistent treatments for similar features. A modest hierarchy of size or weight can make the map's naming system easier to follow.",
                     )),
            _article("contour-reading", "Terrain", ("Follow a contour across the page", "Study the pattern before the detail"),
                     "A contour sketch is an exercise in following a continuous visual pattern.", (
                         "Begin with a simple contour drawing and trace one line through the whole image. Observe its turns and how the neighbouring lines relate to it.",
                         "Compare several small portions of the drawing. Describe their patterns in plain terms such as broad, narrow, closely grouped, or widely spaced.",
                         "Keep the line work clear when adding labels or shading. The additional information should preserve the continuity that makes the pattern readable.",
                     )),
            _article("source-margin", "Records", ("Leave room for the map's sources", "The useful margin of a working map"),
                     "A small source note makes a map easier to revisit and revise.", (
                         "Record the source, date, and purpose beside a working map. Add a note when a feature comes from observation, memory, or another published source.",
                         "Mark unresolved details clearly while drawing. A question in the margin is more useful than a precise-looking symbol whose meaning is uncertain.",
                         "When revising the map, keep a dated copy of the earlier version. The record helps explain why a line, name, or selected area changed.",
                     )),
        ),
    },
    "ceramics": {
        "names": ("Clay Surface", "Form in the Hand", "Kilnside Notes", "Small Vessel Studies"),
        "descriptions": (
            "Observations on ceramic form, surface, and the details of everyday vessels.",
            "A notebook of proportions, material samples, and small design decisions in clay.",
            "Looking at the relationship between a vessel's outline and the way it is handled.",
        ),
        "eyebrow": "Clay & form",
        "about": (
            "This collection looks at ceramics through shape, balance, and surface. The focus is on describing what a piece communicates before turning an observation into another design decision.",
            "Sketches, sample labels, and photographs provide a practical record. The notes concern observation and documentation; material and firing decisions belong to the established procedures of the studio using them.",
        ),
        "caption": "A group of imagined vessel silhouettes, with quiet changes in rim and body.",
        "palettes": {
            "clay-terracotta": ("#F4EAE2", "#44332B", "#856E60", "#B06E4F", "#E8D5C6", "#D5BBA7"),
            "clay-celadon": ("#EDF1E9", "#334239", "#6C7D70", "#638470", "#DAE4D8", "#C0D0BE"),
            "clay-cobalt": ("#F0F0F2", "#29374A", "#6A7483", "#456697", "#DEE3EC", "#C4CEDD"),
        },
        "articles": (
            _article("vessel-outline", "Form", ("Draw the outline first", "A vessel seen as a silhouette"),
                     "An outline makes the relationship between rim, body, and foot easier to compare.", (
                         "Draw several versions of a vessel as simple silhouettes. Keep the height similar while changing the width or the point at which the profile begins to curve.",
                         "Place the drawings beside each other and describe their character. Words such as upright, rounded, narrow, or settled can be more useful than an immediate judgement of preference.",
                         "Choose one outline for a closer study of the rim and base. Those details can change the impression of the whole form.",
                     )),
            _article("handle-relationship", "Use", ("Consider the handle with the body", "Where a handle begins and ends"),
                     "A handle is part of the vessel's overall proportion and movement.", (
                         "Sketch the body and handle together instead of adding the handle as a final detail. Compare its height, opening, and points of attachment with the surrounding shape.",
                         "Use photographs or drawings from more than one angle. A profile that looks balanced from the side can describe a different relationship from above.",
                         "Record the observations that matter during ordinary handling. Let those notes guide the next comparison between two possible forms.",
                     )),
            _article("surface-library", "Samples", ("Keep a small surface library", "Label the sample while it is familiar"),
                     "A well-labelled sample connects a visual result with its working record.", (
                         "Give each sample a short identifier and record the information needed to find its process notes. Keep the identifier visible in photographs as well as on the physical sample.",
                         "Photograph comparable samples under the same light and against a plain background. Include one overall view and one closer view of a useful detail.",
                         "Group samples by the question they help answer. A compact set of relevant comparisons can be more practical than a large collection without labels.",
                     )),
            _article("rim-details", "Details", ("A closer look at the rim", "The small line at the top"),
                     "The rim gives the eye and hand a clear place to meet a vessel.", (
                         "Look at several rim profiles in section drawings. Compare the transition from the outside wall to the edge and then to the inside surface.",
                         "Keep the drawing large enough to describe the change clearly. Add brief notes about the visual weight of the edge and its relationship to the rest of the piece.",
                         "Return to the full silhouette before deciding. A rim detail is most useful when it belongs to the proportions of the vessel around it.",
                     )),
            _article("photographing-form", "Records", ("Photograph a form consistently", "A useful sequence of vessel views"),
                     "A repeatable set of views helps compare pieces made at different times.", (
                         "Choose a small sequence of views: side, top, and one angled photograph. Keep the background and camera position as consistent as the available space allows.",
                         "Include a plain reference for scale in a separate record image. Keep the main photographs uncluttered so that the outline and surface remain easy to examine.",
                         "Store the images with the piece's identifier and a short observation. Consistent records make it easier to recognise a recurring design decision.",
                     )),
            _article("small-series", "Practice", ("Make a series around one question", "Comparing a family of forms"),
                     "A small series can explore one proportion through several related pieces.", (
                         "Write down the single feature that the series will compare. It might be the height of a foot, the width of an opening, or the position of a shoulder.",
                         "Keep a simple drawing of each version beside the working notes. Mark the difference clearly so that it remains visible when the pieces are viewed together.",
                         "Finish the comparison with a short description of what each version suggests. The notes become a starting point for the next, more focused series.",
                     )),
        ),
    },
    "coffee": {
        "names": ("Brew Margin", "The Cup Notebook", "Morning Filter", "Notes Beside a Cup"),
        "descriptions": (
            "A quiet notebook about coffee preparation, tasting language, and repeatable routines.",
            "Small observations from the preparation of an everyday cup of coffee.",
            "Keeping useful records of beans, brewing choices, and the way a cup changes as it cools.",
        ),
        "eyebrow": "Coffee & routine",
        "about": (
            "These pages treat coffee preparation as a small repeatable practice. The notes focus on describing a cup clearly and keeping enough context to make the next comparison useful.",
            "A simple record can include the coffee, equipment, measured inputs, and a few observations. The aim is a routine that remains easy to follow on an ordinary morning.",
        ),
        "caption": "An imagined arrangement of a cup, filter, and the repeating shapes of coffee beans.",
        "palettes": {
            "coffee-oat": ("#F4EFE5", "#3D3027", "#806F5F", "#96704B", "#E8DCC9", "#D6C3AB"),
            "coffee-olive": ("#EFF0E6", "#393E2F", "#747B64", "#747B45", "#E0E3CE", "#CDD2B4"),
            "coffee-copper": ("#F5EBE6", "#45332D", "#8A7064", "#A5664B", "#ECD8CD", "#DDBDAA"),
        },
        "articles": (
            _article("short-brew-record", "Records", ("Keep the brew record short", "Five lines beside the cup"),
                     "A record is useful when it is simple enough to complete regularly.", (
                         "Write down the coffee, brewing method, measured coffee and water, and the time or sequence you followed. Leave a final line for the most noticeable result.",
                         "Use the same order for each entry. A consistent format makes two cups easier to compare without turning a short routine into a long report.",
                         "When a cup is especially pleasing, note the circumstances while they are easy to remember. The next attempt then has a clear starting point.",
                     )),
            _article("change-one-choice", "Practice", ("Change one brewing choice", "A comparison with a clear question"),
                     "One deliberate adjustment gives a comparison a more useful focus.", (
                         "Begin with a familiar preparation and choose one detail to adjust. Keep the remaining steps as close to the earlier routine as practical.",
                         "Write the question before tasting. You might be comparing the finish, the balance of the cup, or how clearly a particular impression stands out.",
                         "Describe the difference before choosing a favourite. The description will be more useful later than a score with no explanation.",
                     )),
            _article("tasting-language", "Tasting", ("Use words that describe your cup", "A small personal tasting vocabulary"),
                     "Plain, familiar descriptions can make a tasting note easier to revisit.", (
                         "Start with broad observations such as light, rounded, dry, bright, or lingering. Add a more specific comparison only when it helps communicate what you noticed.",
                         "Keep the note connected to the actual cup and moment. A description can change as the drink cools or as you return to it after a short pause.",
                         "Review older notes for words you use consistently. A small reliable vocabulary gives your records a useful continuity.",
                     )),
            _article("cooling-cup", "Observation", ("Return to the cup as it cools", "Three moments in one tasting"),
                     "A few spaced observations can describe a cup more fully than one quick impression.", (
                         "Take an initial note, then return to the cup at two later moments. Keep the descriptions brief enough that the exercise remains part of an ordinary tasting.",
                         "Look for what stays familiar and what becomes easier to notice. Record your impressions without assuming that every difference requires a change to the recipe.",
                         "Read the three notes together. The sequence can suggest which part of the experience matters most to your preference.",
                     )),
            _article("repeatable-station", "Routine", ("Arrange a repeatable brewing space", "Give each tool a clear place"),
                     "A simple arrangement helps the preparation proceed in a familiar order.", (
                         "Lay out the equipment in the order it will be used. Keep the scale, coffee, water, and receiving vessel easy to reach without crowding the working area.",
                         "Remove objects that are unrelated to the current preparation. A clear space makes it easier to notice which step has been completed and which comes next.",
                         "After brewing, return the equipment to its usual place. A routine is easier to repeat when the next session begins from the same arrangement.",
                     )),
            _article("bean-label", "Reference", ("Keep the information from the bag", "A useful reference for the next cup"),
                     "The original label provides context that a tasting note alone can miss.", (
                         "Copy the coffee's name and the information supplied on its label into your notebook. Keep a photograph when that is quicker than transcribing the details.",
                         "Add the date on which you opened the bag and began using it. This gives later observations a place within the same sequence of preparations.",
                         "Store the label record beside the brew notes. The combination is more useful than trying to reconstruct the coffee's identity from a remembered flavour.",
                     )),
        ),
    },
    "acoustics": {
        "names": ("Listening Room Notes", "Sound in Place", "The Quiet Interval", "Rooms and Resonance"),
        "descriptions": (
            "Observations about listening spaces, familiar sounds, and the character of a room.",
            "A collection of listening exercises and notes about sound in everyday interiors.",
            "Looking at a room through the sounds that begin, move, and fade within it.",
        ),
        "eyebrow": "Sound & space",
        "about": (
            "These notes approach a listening space through careful description. A familiar recording, a short spoken passage, or an ordinary room sound provides a repeatable point of comparison.",
            "The exercises are informal observations rather than acoustic measurements. Record the position, surroundings, and listening level so that a later comparison has the same context.",
        ),
        "caption": "An imagined field of wave lines and repeated intervals across a quiet surface.",
        "palettes": {
            "sound-indigo": ("#EEF0F7", "#30364D", "#737B96", "#596EAA", "#DEE4F2", "#C6D1E6"),
            "sound-sand": ("#F4F0E6", "#3C3930", "#827B68", "#8D8051", "#E9E1CC", "#D8CCAA"),
            "sound-teal": ("#EAF2F1", "#283F41", "#668384", "#407E82", "#D5E6E3", "#BCD5D2"),
        },
        "articles": (
            _article("listening-position", "Position", ("Record the listening position", "A small map of where you listened"),
                     "A position note gives a listening comparison a useful physical context.", (
                         "Sketch the room and mark the place where you listened. Include the sound source and the nearby surfaces or furniture that define that position.",
                         "Choose a short familiar passage and keep the playback level comfortable. Describe what you notice before moving to another position.",
                         "Place the notes beside the sketch. The record can help separate an impression of the room from a memory of the passage itself.",
                     )),
            _article("sound-ending", "Listening", ("Listen to the end of a sound", "The interval after a phrase"),
                     "The moment after a sound can be as useful to describe as its beginning.", (
                         "Choose a familiar short sound or spoken phrase. After it ends, pay attention to the way the room returns to its ordinary background.",
                         "Use simple descriptions such as brief, extended, distinct, or blended. Keep the observation tied to the same position and surrounding conditions.",
                         "Repeat the exercise on another day before drawing a strong conclusion. A small collection of notes is more informative than one isolated impression.",
                     )),
            _article("background-inventory", "Environment", ("Make a background sound inventory", "The sounds already in the room"),
                     "A quiet minute can reveal the ordinary sounds that form a room's background.", (
                         "Sit in one place and list the sounds you can distinguish without searching for them. Note which remain steady and which appear only briefly.",
                         "Group the notes by what you can reasonably identify. Use a question mark when the source is uncertain instead of assigning it a confident label.",
                         "Return to the inventory at another time. The comparison describes how the space is used as well as how it sounds.",
                     )),
            _article("spoken-passage", "Reference", ("Keep a familiar spoken passage", "A repeatable listening reference"),
                     "A short piece of speech provides a consistent starting point for room notes.", (
                         "Select a passage whose words and pace are easy to recognise. Keep the same recording and playback arrangement when comparing positions or small room changes.",
                         "Write about how easily the words can be followed and how the pauses feel. Avoid changing several parts of the setup during the same comparison.",
                         "Keep the passage's details beside the notes. A reference is useful because it can be returned to under familiar conditions.",
                     )),
            _article("room-sketch", "Structure", ("Draw the room before adjusting it", "A visual record of the listening space"),
                     "A simple room drawing can clarify the arrangement behind a listening observation.", (
                         "Mark the main boundaries, openings, large furnishings, and listening positions. The drawing only needs enough detail to identify the arrangement being described.",
                         "When you make a small change, draw it on a second copy. Keep a short note about the purpose of the change and the reference used to compare it.",
                         "Save both versions with the listening notes. The record helps explain an earlier decision without relying on memory alone.",
                     )),
            _article("comparison-notes", "Practice", ("Separate observation from preference", "Two useful lines in a listening note"),
                     "A description and a preference answer different parts of a comparison.", (
                         "Write one line about what seemed different, then another about which version you preferred. Give each line enough context to remain meaningful later.",
                         "Use the same reference and a comfortable, consistent level. Pause when the comparison stops producing a clear observation.",
                         "Review the notes after some time has passed. A preference that remains useful across several ordinary listening sessions deserves closer attention.",
                     )),
        ),
    },
    "printmaking": {
        "names": ("Paper and Pressure", "The Proof Notebook", "Ink Margin", "Small Edition Studies"),
        "descriptions": (
            "Notes about print surfaces, proof sheets, and the rhythm of repeated marks.",
            "A collection of observations on ink, paper, and the making of a clear image.",
            "Keeping a useful record of proofs, compositions, and small changes between impressions.",
        ),
        "eyebrow": "Ink & paper",
        "about": (
            "This notebook considers prints through the decisions visible on a proof sheet. A border, a repeated mark, or a change in the relationship between light and dark can give a comparison its focus.",
            "The notes concern composition and documentation. A short identifier and a clear description help connect each impression to the working process that produced it.",
        ),
        "caption": "A procedural study of overlapping shapes, interrupted lines, and a restrained ink palette.",
        "palettes": {
            "print-carbon": ("#F4F1E9", "#292B2A", "#737770", "#505D55", "#E2E4D9", "#CBCFC0"),
            "print-rust": ("#F6EDE4", "#49342C", "#8A7364", "#B36C48", "#ECD8C5", "#DEBFA1"),
            "print-blue": ("#EEF1F5", "#2A3648", "#6D7C91", "#4A6B98", "#DEE5EE", "#C5D1E0"),
        },
        "articles": (
            _article("proof-identifier", "Records", ("Label every useful proof", "A proof sheet with enough context"),
                     "A short identifier connects an impression with the notes that explain it.", (
                         "Choose a simple naming sequence and use it consistently. Record the image, date, and version beside the observations that distinguish one proof from the next.",
                         "Photograph the identifier together with the sheet. A separate clean image can document the composition, while the record image preserves its working context.",
                         "Keep the most informative proofs even when they are unfinished. A visible intermediate decision can be useful during a later project.",
                     )),
            _article("negative-space", "Composition", ("Look at the unprinted shapes", "Reading the spaces between marks"),
                     "The empty portions of an image contribute to its structure and pace.", (
                         "Study the composition as a group of light and dark shapes. Trace the spaces between the main marks and compare their size and direction.",
                         "Make a small paper sketch before changing the working surface. This gives the proposed adjustment a clear form that can be considered beside the existing proof.",
                         "Return to the whole image after studying the details. A useful change should support the composition at the size where it will be viewed.",
                     )),
            _article("border-study", "Edges", ("Give the border a separate study", "The image and its surrounding paper"),
                     "A border influences the way an image sits on the sheet.", (
                         "Place the same image within several paper outlines. Compare narrow, broad, even, and deliberately uneven margins before choosing a final arrangement.",
                         "Look at the relationship between the image's strongest direction and the surrounding space. Include any caption or identifier that belongs in the finished layout.",
                         "Keep the preferred arrangement as a simple reference drawing. It can save repeated decisions when preparing a related group of prints.",
                     )),
            _article("repeated-marks", "Rhythm", ("Vary one mark within a sequence", "A rhythm made from simple shapes"),
                     "A repeated element creates a clear setting for a small deliberate variation.", (
                         "Begin with a short row of similar marks. Change one feature, such as width, spacing, or orientation, while keeping the rest of the sequence familiar.",
                         "Compare the row at close range and from farther away. Notice whether the variation reads as a focal point, an interruption, or part of a gradual change.",
                         "Use the observation to make a second sequence. A few focused studies can suggest several directions for a larger composition.",
                     )),
            _article("paper-observations", "Material", ("Describe the paper beside the proof", "A small paper reference library"),
                     "A paper sample is more useful when its identity and observations remain together.", (
                         "Keep a small labelled sample with the information supplied by its maker. Record the details needed to identify the same paper again.",
                         "Add an observation about the particular impression you made on it. Describe the visible result without assuming that another process would produce the same effect.",
                         "Group samples around a current question. A compact selection makes it easier to compare the papers that are relevant to the next piece.",
                     )),
            _article("proof-comparison", "Practice", ("Compare proofs in a fixed order", "A sequence of visible decisions"),
                     "An ordered set of proofs can make the development of an image easier to understand.", (
                         "Lay out a small group of proofs in the order they were made. Place a short note beside each one describing the intended change.",
                         "Look for the point where a decision became clearer, and the point where another detail became less useful. Keep both observations in the record.",
                         "Finish with a concise description of the next question. The comparison then becomes a practical guide for continuing the work.",
                     )),
        ),
    },
    "coastal": {
        "names": ("Shoreline Notebook", "Along the Waterline", "Coastal Observations", "The Distant Shore"),
        "descriptions": (
            "Small observations of coastal light, distant lines, and the textures of a shoreline.",
            "A visual notebook of the meeting between land, water, and open sky.",
            "Looking closely at repeated forms, changing colours, and the scale of a coastal view.",
        ),
        "eyebrow": "Shore & horizon",
        "about": (
            "These notes describe a coast through visible details: an edge in the distance, a group of textures, or a change in the colour of the water. Short sketches and clear labels keep the observations connected.",
            "The exercises can be made from a photograph or a familiar public viewpoint. They focus on looking and recording, without claiming to describe the conditions of a particular place.",
        ),
        "caption": "An imagined shoreline assembled from layered water, low land, and a broad sky.",
        "palettes": {
            "shore-seaglass": ("#EDF3EF", "#2D4540", "#6C8880", "#478B7E", "#D5E7DD", "#BBD7C9"),
            "shore-sand": ("#F5F0E5", "#454137", "#89806B", "#9B8653", "#EAE0C8", "#DACEAA"),
            "shore-harbour": ("#EAF0F5", "#293F51", "#6A8396", "#487A9F", "#D5E2ED", "#BAD0E0"),
        },
        "articles": (
            _article("horizon-placement", "Composition", ("Place the horizon deliberately", "Three versions of one coastal view"),
                     "Moving the horizon within a sketch changes the balance of land, water, and sky.", (
                         "Draw the same simple view with the horizon low, central, and high on the page. Keep the main shapes consistent while changing their relative amount of space.",
                         "Describe where your attention goes in each version. The comparison can suggest whether the view is primarily about the sky, the water, or the near edge of land.",
                         "Choose one arrangement for a more detailed study. Keep the other sketches as a reminder of the alternatives that were considered.",
                     )),
            _article("shore-textures", "Texture", ("Make a small texture inventory", "Patterns near the waterline"),
                     "A few clearly described textures can give a visual note its sense of place.", (
                         "Choose a photograph or a familiar view and identify several distinct textures. Sketch a small sample of each without trying to describe the entire scene at once.",
                         "Use plain labels such as ridged, smooth, scattered, or layered. Add a short note about the size of the pattern within the larger view.",
                         "Compare the samples on one page. Their differences can help decide which details deserve emphasis in a later drawing.",
                     )),
            _article("colour-strips", "Colour", ("Keep a strip of observed colours", "A coastal palette in a few samples"),
                     "A short sequence of colour samples can preserve an impression of changing light.", (
                         "Select a few colours from the same view and place them in a narrow strip. Note which belong to the sky, water, distant land, or nearby surfaces.",
                         "Keep the source and observation time beside the strip when they are known. If the study comes from an image, record that context as well.",
                         "Return to the strip while making a larger composition. It can provide a useful starting palette without requiring every part of the scene to match exactly.",
                     )),
            _article("distant-landmarks", "Distance", ("Use a landmark to describe scale", "A small shape across open water"),
                     "One recognisable shape can provide a reference within a broad coastal view.", (
                         "Choose a distant feature that can be identified clearly in the source image or view. Sketch its outline beside a larger drawing of the surrounding space.",
                         "Compare the feature's height with the horizon and nearby shapes. The aim is a useful visual relationship, so record uncertainty instead of adding unsupported precision.",
                         "Keep the landmark simple in the final composition. A few well-placed lines may carry the reference more clearly than a crowded description.",
                     )),
            _article("repeated-view", "Observation", ("Return to the same view", "A sequence from one viewpoint"),
                     "A consistent viewpoint makes changes between observations easier to describe.", (
                         "Choose a view that can be recorded from the same ordinary position. Keep the framing similar and write down the available context for each observation.",
                         "Compare the sequence for changes in light, visible shapes, and the distribution of colour. Describe what the images show without assuming a cause for every difference.",
                         "Select a few frames that explain the sequence clearly. A small, well-labelled group is easier to revisit than a large set of nearly identical images.",
                     )),
            _article("edge-drawing", "Lines", ("Follow one edge across the page", "A shoreline drawn as a continuous line"),
                     "Tracing a single boundary can reveal the rhythm of a complicated scene.", (
                         "Choose one visible edge and follow it through a sketch. Let the line record its broad turns before adding smaller interruptions and details.",
                         "Notice where the line changes pace through repeated bends, long stretches, or short angular sections. Describe those changes in the margin.",
                         "Use the study as a framework for a second drawing with a few additional shapes. Keep the original line legible as the composition becomes more detailed.",
                     )),
        ),
    },
}
