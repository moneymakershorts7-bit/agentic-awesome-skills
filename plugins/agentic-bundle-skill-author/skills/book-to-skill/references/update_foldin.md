# Update and Fold-in Workflow

Workflow for adding new chapters, errata, or related volumes to an existing skill.

## Procedure
1. **Locate Target Skill**: Identify the existing skill in `SKILLS_HOME`.
2. **Extract New Material**: Run `scripts/extract.py` on new source files.
3. **Analyze Delta**: Identify new chapters, modified concepts, or extended frameworks.
4. **Merge Artifacts**:
   - Add new chapters sequentially into `chapters/`.
   - Update `glossary.md` with new terms.
   - Update `patterns.md` and `cheatsheet.md`.
   - Update `SKILL.md` index and overview.
5. **Re-validate**: Run `tools/scan_generated_skill.py` to ensure consistency.
