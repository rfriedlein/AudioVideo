#!/bin/bash
## Search recurivly for new files v.01 ##


find $1 -type f -exec stat --format '%Y :%y %n' {} \; | sort -nr | cut -d: -f2- | head
