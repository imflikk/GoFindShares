# Overview
This is mostly to practice using Go for making tools, but is meant to imitate how [Snaffler](https://github.com/SnaffCon/Snaffler) works by walking SMB shares and searching files for keywords.

![image](https://github.com/imflikk/GoFindShares/assets/58894272/5168db80-0541-4999-9687-6a08e4f08a64)

# Usage
It currently takes several possible parameters, with some being optional.  It requires at least an individual target (-target) or a list of IPs/hostnames (-file).  

Optional arguments include: a set of credentials (defaults to anonymous if not provided) and a keyword to search for in files (defaults to "password" if not provided.

![image](https://github.com/imflikk/GoFindShares/assets/58894272/890bd728-3582-4134-a3ba-a1394306aae1)

# To-Do
- [x] Command line option to provide input file of SMB servers
- [x] Ability to check content of found files for keywords
  - [ ] Expand this to allow for multiple keywords
  - [x] Add file size limit for keyword checking
- [ ] Output findings to more readable format (CSV?)
- [ ] Re-format into a better Go project structure
- [x] Add concurrency support
  - Added goroutines for checking each share, but I'm pretty bad at concurrency, so not entirely sure it's working correctly without testing in a large environment where it can be fully utilized.




