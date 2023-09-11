# GoFindShares

This is mostly to practice using Go for making tools, but is meant to imitate how [Snaffler](https://github.com/SnaffCon/Snaffler) works.

![image](https://github.com/imflikk/GoFindShares/assets/58894272/5168db80-0541-4999-9687-6a08e4f08a64)

### TODO
- [x] Command line option to provide input file of SMB servers
- [x] Ability to check content of found files for keywords
  - [ ] Expand this to allow for multiple keywords
  - [x] Add file size limit for keyword checking
- [ ] Output findings to more readable format (CSV?)
- [ ] Re-format into a better Go project structure
- [x] Add concurrency support
  - Added goroutines for checking each share, but I'm pretty bad at concurrency, so not entirely sure it's working correctly without testing in a large environment where it can be fully utilized.




