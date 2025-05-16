# OSINT CTF Guide for Beginners

## What is OSINT?

Open Source Intelligence (OSINT) in CTF competitions involves finding information from publicly available sources to solve challenges. Unlike technical exploitation, OSINT focuses on:

- Discovering information about people, organizations, or events
- Analyzing images for hidden metadata or location details
- Finding connections between seemingly unrelated pieces of information
- Using search engines and public databases effectively
- Thinking like an investigator rather than a hacker

OSINT challenges test your research skills, attention to detail, and ability to connect dots across different information sources.

## Common OSINT CTF Challenge Types

### 1. **Image Analysis**
- Identifying locations from photographs
- Extracting metadata from images
- Finding original sources of modified images

### 2. **Person/Identity Research**
- Finding information about fictional or real individuals
- Tracing usernames across multiple platforms
- Connecting social media accounts

### 3. **Geolocation Challenges**
- Identifying locations from limited visual clues
- Finding addresses or coordinates
- Mapping locations from descriptions

### 4. **Website/Domain Investigation**
- Analyzing website ownership information
- Finding historical versions of websites
- Discovering hidden subdirectories or pages

### 5. **Social Media Intelligence**
- Finding specific posts or information on social platforms
- Analyzing connections between accounts
- Extracting data from public profiles

## Essential OSINT Tools

### Image Analysis

**1. ExifTool**
- Extracts metadata from images
- **When to use**: When you need to find hidden information in image files

**2. Google Reverse Image Search / TinEye**
- Find similar or original images
- **When to use**: When you need to trace the origin of an image

**3. Yandex Images**
- Often better than Google for face recognition and partial matches
- **When to use**: When Google image search doesn't yield results

### Geolocation

**1. Google Maps / Earth**
- Satellite and street view imagery
- **When to use**: For confirming locations or virtual "travel"

**2. GeoGuessr (technique, not just the game)**
- Using visual clues to determine location
- **When to use**: When you only have visual elements to work with

**3. SunCalc**
- Analyzes sun position in photos
- **When to use**: When you need to determine time/date from shadows

### Website Research

**1. WHOIS Lookup**
- Domain registration information
- **When to use**: To find information about website ownership

**2. Wayback Machine**
- Historical snapshots of websites
- **When to use**: To view previous versions of websites

**3. DNSdumpster**
- DNS information and subdomains
- **When to use**: To discover hidden subdomains

### Social Media Research

**1. Sherlock**
- Username search across multiple platforms
- **When to use**: To track usernames across different sites

**2. Social Analyzer**
- Analyzes profiles across platforms
- **When to use**: For comprehensive profile analysis

**3. Twint (Twitter Intelligence)**
- Advanced Twitter searching without API
- **When to use**: For deep Twitter research

### General Research

**1. Google Dorks**
- Advanced search operators
- **When to use**: For precise search queries

**2. Intelligence X**
- Search engine for leaked data, domains, etc.
- **When to use**: When looking for sensitive or leaked information

**3. The Harvester**
- Gathers emails, subdomains, etc.
- **When to use**: For collecting public data about a target

## Step-by-Step Approach to OSINT Challenges

1. **Analyze the Challenge**
   - Identify all provided clues and information
   - Look for hidden details in images, text, or files
   - Note usernames, email formats, or naming patterns

2. **Initial Research**
   - Use search engines with precise queries
   - Check metadata of any provided files
   - Look for unique identifiers (usernames, emails, etc.)

3. **Expand Your Search**
   - Follow leads across multiple platforms
   - Connect pieces of information
   - Use specialized tools based on the challenge type

4. **Verify and Cross-Reference**
   - Confirm findings with multiple sources
   - Check for inconsistencies or red herrings
   - Build a timeline or relationship map if helpful

5. **Flag Identification**
   - Look for information that matches flag format
   - Combine discovered elements if necessary
   - Convert findings to the required format

## Practical OSINT Tips

- **Start broad, then narrow down** - Begin with general searches and refine
- **Check image metadata immediately** - Use ExifTool on all provided images
- **Note every detail** - Small clues often lead to big discoveries
- **Create a research log** - Document every finding and source
- **Use incognito/private browsing** - Prevents search history from affecting results
- **Try multiple search engines** - Google, Bing, DuckDuckGo, and Yandex give different results
- **Check social media account creation dates** - Timeline information is often crucial
- **Look for reflections in images** - Windows, glasses, and water can reveal hidden details
- **Pay attention to backgrounds** - Street signs, landmarks, or storefronts provide location clues
- **Search for exact phrases in quotes** - Use "quotation marks" for exact matches
- **Use advanced search operators** - `site:`, `filetype:`, `inurl:`, etc.
- **Check for languages and alphabets** - Identifying languages can narrow down locations
- **Look for shadows in images** - Can help determine time of day and direction
- **Check usernames across platforms** - People often reuse usernames

## Essential Google Dorks for OSINT

```
site:example.com                   # Limits search to specific website
filetype:pdf                       # Searches for specific file types
inurl:admin                        # Finds pages with specific words in URL
intitle:"index of"                 # Finds directory listings
"John Doe" filetype:pdf            # Combines techniques
```

## Practice Resources

- **Beginner-friendly platforms**:
  - Trace Labs CTF
  - Geoguessr
  - PicoCTF (OSINT challenges)
  - CTFlearn (OSINT category)

- **Learning materials**:
  - "Open Source Intelligence Techniques" by Michael Bazzell
  - OSINT Framework website (osintframework.com)
  - IntelTechniques.com

Remember that OSINT is about patience and attention to detail. Often the smallest clue can lead to the solution. Document everything and approach each challenge methodically, like a detective following leads!
