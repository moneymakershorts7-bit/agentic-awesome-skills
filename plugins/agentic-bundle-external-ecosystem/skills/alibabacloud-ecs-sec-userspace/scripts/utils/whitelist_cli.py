"""Whitelist Management CLI Commands

Provides CLI commands for managing whitelist:
- whitelist suggestions: View learning suggestions
- whitelist accept: Accept a suggestion
- whitelist reject: Reject a suggestion
- whitelist stats: View learning statistics
- whitelist clear: Clear all learning data
- whitelist add: Add tool to whitelist
- whitelist remove: Remove tool from whitelist
- whitelist list: List all whitelist entries
- whitelist export: Export whitelist configuration
- whitelist import: Import whitelist configuration
- whitelist add-prefix: Add trusted prefix
- whitelist add-category: Add custom category
"""
import sys
import os
import json
from datetime import datetime, timezone

# Import whitelist loader types
from .whitelist_loader import (
    USER_WHITELIST_FILE,
    SYSTEM_WHITELIST_DIR,
    UserWhitelistConfig,
)


def setup_whitelist_commands(subparsers) -> None:
    """Setup whitelist management subcommands
    
    Args:
        subparsers: ArgumentParser subparsers object
    """
    # Main whitelist command
    whitelist_parser = subparsers.add_parser(
        "whitelist",
        help="Whitelist management commands (learning + user-defined)"
    )
    whitelist_subparsers = whitelist_parser.add_subparsers(
        dest="whitelist_command",
        help="Whitelist subcommands"
    )
    
    # ============================================
    # User-defined whitelist commands (NEW)
    # ============================================
    
    # whitelist add
    add_parser = whitelist_subparsers.add_parser(
        "add",
        help="Add a tool to user-defined whitelist"
    )
    add_parser.add_argument(
        "--tool",
        type=str,
        required=True,
        help="Tool name to add to whitelist"
    )
    add_parser.add_argument(
        "--category",
        type=str,
        default="custom_tools",
        help="Category name (default: custom_tools)"
    )
    add_parser.add_argument(
        "--confidence",
        type=float,
        default=0.10,
        help="Confidence boost value (0.0-1.0, default: 0.10)"
    )
    add_parser.add_argument(
        "--description",
        type=str,
        default="",
        help="Description of this whitelist entry"
    )
    add_parser.add_argument(
        "--level",
        type=str,
        choices=["system", "workspace"],
        default="workspace",
        help="Configuration level (default: workspace)"
    )
    add_parser.add_argument(
        "--workspace-dir",
        type=str,
        default="/data/sec-userspace/workspace",
        help="Workspace directory (default: /data/sec-userspace/workspace)"
    )
    add_parser.set_defaults(func=handle_whitelist_add)
    
    # whitelist remove
    remove_parser = whitelist_subparsers.add_parser(
        "remove",
        help="Remove a tool from user-defined whitelist"
    )
    remove_parser.add_argument(
        "--tool",
        type=str,
        required=True,
        help="Tool name to remove from whitelist"
    )
    remove_parser.add_argument(
        "--category",
        type=str,
        default=None,
        help="Category name (optional, removes from all categories if not specified)"
    )
    remove_parser.add_argument(
        "--level",
        type=str,
        choices=["system", "workspace"],
        default="workspace",
        help="Configuration level (default: workspace)"
    )
    remove_parser.add_argument(
        "--workspace-dir",
        type=str,
        default="/data/sec-userspace/workspace",
        help="Workspace directory"
    )
    remove_parser.set_defaults(func=handle_whitelist_remove)
    
    # whitelist list
    list_parser = whitelist_subparsers.add_parser(
        "list",
        help="List all whitelist entries (built-in + user-defined)"
    )
    list_parser.add_argument(
        "--format",
        type=str,
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)"
    )
    list_parser.add_argument(
        "--category",
        type=str,
        default=None,
        help="Filter by category name"
    )
    list_parser.add_argument(
        "--workspace-dir",
        type=str,
        default="/data/sec-userspace/workspace",
        help="Workspace directory"
    )
    list_parser.set_defaults(func=handle_whitelist_list)
    
    # whitelist export
    export_parser = whitelist_subparsers.add_parser(
        "export",
        help="Export user-defined whitelist configuration"
    )
    export_parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output file path (default: stdout)"
    )
    export_parser.add_argument(
        "--level",
        type=str,
        choices=["system", "workspace"],
        default="workspace",
        help="Configuration level to export (default: workspace)"
    )
    export_parser.add_argument(
        "--workspace-dir",
        type=str,
        default="/data/sec-userspace/workspace",
        help="Workspace directory"
    )
    export_parser.set_defaults(func=handle_whitelist_export)
    
    # whitelist import
    import_parser = whitelist_subparsers.add_parser(
        "import",
        help="Import user-defined whitelist configuration"
    )
    import_parser.add_argument(
        "input_file",
        type=str,
        help="Input JSON file path"
    )
    import_parser.add_argument(
        "--level",
        type=str,
        choices=["system", "workspace"],
        default="workspace",
        help="Configuration level to import to (default: workspace)"
    )
    import_parser.add_argument(
        "--merge",
        action="store_true",
        help="Merge with existing configuration (default: replace)"
    )
    import_parser.add_argument(
        "--workspace-dir",
        type=str,
        default="/data/sec-userspace/workspace",
        help="Workspace directory"
    )
    import_parser.set_defaults(func=handle_whitelist_import)
    
    # whitelist add-prefix
    prefix_parser = whitelist_subparsers.add_parser(
        "add-prefix",
        help="Add a trusted prefix to whitelist"
    )
    prefix_parser.add_argument(
        "--prefix",
        type=str,
        required=True,
        help="Trusted prefix pattern (e.g., kprobe__company_)"
    )
    prefix_parser.add_argument(
        "--reason",
        type=str,
        required=True,
        help="Reason for trusting this prefix"
    )
    prefix_parser.add_argument(
        "--level",
        type=str,
        choices=["system", "workspace"],
        default="workspace",
        help="Configuration level (default: workspace)"
    )
    prefix_parser.add_argument(
        "--workspace-dir",
        type=str,
        default="/data/sec-userspace/workspace",
        help="Workspace directory"
    )
    prefix_parser.set_defaults(func=handle_whitelist_add_prefix)
    
    # whitelist add-category
    category_parser = whitelist_subparsers.add_parser(
        "add-category",
        help="Add a custom category to whitelist"
    )
    category_parser.add_argument(
        "--name",
        type=str,
        required=True,
        help="Category name"
    )
    category_parser.add_argument(
        "--tools",
        type=str,
        nargs="+",
        required=True,
        help="Tool names in this category"
    )
    category_parser.add_argument(
        "--confidence",
        type=float,
        default=0.10,
        help="Confidence boost value (default: 0.10)"
    )
    category_parser.add_argument(
        "--description",
        type=str,
        default="",
        help="Category description"
    )
    category_parser.add_argument(
        "--level",
        type=str,
        choices=["system", "workspace"],
        default="workspace",
        help="Configuration level (default: workspace)"
    )
    category_parser.add_argument(
        "--workspace-dir",
        type=str,
        default="/data/sec-userspace/workspace",
        help="Workspace directory"
    )
    category_parser.set_defaults(func=handle_whitelist_add_category)
    
    # ============================================
    # Existing whitelist learning commands
    # ============================================
    
    # whitelist suggestions
    suggestions_parser = whitelist_subparsers.add_parser(
        "suggestions",
        help="View whitelist learning suggestions"
    )
    suggestions_parser.add_argument(
        "--status",
        type=str,
        choices=["pending", "accepted", "rejected", "all"],
        default="pending",
        help="Filter by suggestion status (default: pending)"
    )
    suggestions_parser.add_argument(
        "--workspace-dir",
        type=str,
        default="/data/sec-userspace/workspace",
        help="Workspace directory (default: /data/sec-userspace/workspace)"
    )
    suggestions_parser.set_defaults(func=handle_whitelist_suggestions)
    
    # whitelist accept
    accept_parser = whitelist_subparsers.add_parser(
        "accept",
        help="Accept a whitelist suggestion"
    )
    accept_parser.add_argument(
        "tool_name",
        type=str,
        help="Name of the tool to accept"
    )
    accept_parser.add_argument(
        "--workspace-dir",
        type=str,
        default="/data/sec-userspace/workspace",
        help="Workspace directory (default: /data/sec-userspace/workspace)"
    )
    accept_parser.set_defaults(func=handle_whitelist_accept)
    
    # whitelist reject
    reject_parser = whitelist_subparsers.add_parser(
        "reject",
        help="Reject a whitelist suggestion"
    )
    reject_parser.add_argument(
        "tool_name",
        type=str,
        help="Name of the tool to reject"
    )
    reject_parser.add_argument(
        "--workspace-dir",
        type=str,
        default="/data/sec-userspace/workspace",
        help="Workspace directory (default: /data/sec-userspace/workspace)"
    )
    reject_parser.set_defaults(func=handle_whitelist_reject)
    
    # whitelist stats
    stats_parser = whitelist_subparsers.add_parser(
        "stats",
        help="View whitelist learning statistics"
    )
    stats_parser.add_argument(
        "--workspace-dir",
        type=str,
        default="/data/sec-userspace/workspace",
        help="Workspace directory (default: /data/sec-userspace/workspace)"
    )
    stats_parser.set_defaults(func=handle_whitelist_stats)
    
    # whitelist clear
    clear_parser = whitelist_subparsers.add_parser(
        "clear",
        help="Clear all whitelist learning data"
    )
    clear_parser.add_argument(
        "--force",
        action="store_true",
        help="Skip confirmation prompt"
    )
    clear_parser.add_argument(
        "--workspace-dir",
        type=str,
        default="/data/sec-userspace/workspace",
        help="Workspace directory (default: /data/sec-userspace/workspace)"
    )
    clear_parser.set_defaults(func=handle_whitelist_clear)


def handle_whitelist_suggestions(args) -> int:
    """Handle 'whitelist suggestions' command
    
    Args:
        args: Parsed arguments
        
    Returns:
        int: Exit code (0 for success, 1 for error)
    """
    try:
        from .whitelist_learner import WhitelistLearner
        
        learner = WhitelistLearner(args.workspace_dir)
        
        if args.status == "all":
            suggestions = learner.get_suggestions()
        else:
            suggestions = learner.get_suggestions(status=args.status)
        
        if not suggestions:
            print(f"No {args.status} suggestions found.")
            return 0
        
        print(f"\n{'='*70}")
        print(f"Whitelist Learning Suggestions ({args.status})")
        print(f"{'='*70}\n")
        
        for i, sug in enumerate(suggestions, 1):
            print(f"[{i}] {sug.tool_name}")
            print(f"    Confidence: {sug.confidence:.1%}")
            print(f"    Occurrences: {sug.occurrence_count}")
            print(f"    Clean Scan Ratio: {sug.clean_scan_ratio:.1%}")
            print(f"    First Seen: {sug.first_seen}")
            print(f"    Last Seen: {sug.last_seen}")
            print(f"    Reason: {sug.reason}")
            if sug.program_path:
                print(f"    Path: {sug.program_path}")
            print(f"    Status: {sug.status}")
            print()
        
        print(f"Total: {len(suggestions)} suggestion(s)")
        print("\nTo accept a suggestion, run:")
        print("  sec-userspace whitelist accept <tool-name>")
        print("\nTo reject a suggestion, run:")
        print("  sec-userspace whitelist reject <tool-name>")
        
        return 0
        
    except (ImportError, OSError, KeyError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def handle_whitelist_accept(args) -> int:
    """Handle 'whitelist accept' command
    
    Args:
        args: Parsed arguments
        
    Returns:
        int: Exit code
    """
    try:
        from .whitelist_learner import WhitelistLearner
        
        learner = WhitelistLearner(args.workspace_dir)
        
        if learner.accept_suggestion(args.tool_name):
            print(f"Accepted suggestion: {args.tool_name}")
            print("\nNote: This marks the suggestion as accepted in the learning system.")
            print("To add it to the actual whitelist, use:")
            print(f"  sec-userspace --add-whitelist {args.tool_name}")
            return 0
        else:
            print(f"Suggestion not found: {args.tool_name}")
            return 1
            
    except (ImportError, OSError, KeyError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def handle_whitelist_reject(args) -> int:
    """Handle 'whitelist reject' command
    
    Args:
        args: Parsed arguments
        
    Returns:
        int: Exit code
    """
    try:
        from .whitelist_learner import WhitelistLearner
        
        learner = WhitelistLearner(args.workspace_dir)
        
        if learner.reject_suggestion(args.tool_name):
            print(f"Rejected suggestion: {args.tool_name}")
            print("The system will not suggest this program again.")
            return 0
        else:
            print(f"Suggestion not found: {args.tool_name}")
            return 1
            
    except (ImportError, OSError, KeyError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def handle_whitelist_stats(args) -> int:
    """Handle 'whitelist stats' command
    
    Args:
        args: Parsed arguments
        
    Returns:
        int: Exit code
    """
    try:
        from .whitelist_learner import WhitelistLearner
        
        learner = WhitelistLearner(args.workspace_dir)
        stats = learner.get_stats()
        
        print(f"\n{'='*70}")
        print("Whitelist Learning Statistics")
        print(f"{'='*70}\n")
        
        print("Observation Window:")
        print(f"  Window Size: {stats['observation_window_days']} days")
        print(f"  Total Observations: {stats['total_observations']}")
        print(f"  Observations in Window: {stats['window_observations']}")
        print(f"  Unique Programs in Window: {stats['unique_programs_in_window']}")
        print()
        
        print("Scan Results (in window):")
        print(f"  Clean Observations: {stats['clean_observations']}")
        print(f"  Alert Observations: {stats['alert_observations']}")
        print()
        
        print("Suggestions:")
        print(f"  Pending: {stats['suggestions']['pending']}")
        print(f"  Accepted: {stats['suggestions']['accepted']}")
        print(f"  Rejected: {stats['suggestions']['rejected']}")
        print()
        
        print("Learning Configuration:")
        print(f"  Min Occurrences: {stats['min_occurrences']}")
        print(f"  Confidence Threshold: {stats['confidence_threshold']:.1%}")
        print()
        
        return 0
        
    except (ImportError, OSError, KeyError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def handle_whitelist_clear(args) -> int:
    """Handle 'whitelist clear' command
    
    Args:
        args: Parsed arguments
        
    Returns:
        int: Exit code
    """
    try:
        from .whitelist_learner import WhitelistLearner
        
        if not args.force:
            response = input(
                "This will delete all whitelist learning data. Are you sure? [y/N]: "
            )
            if response.lower() != 'y':
                print("Aborted.")
                return 0
        
        learner = WhitelistLearner(args.workspace_dir)
        deleted = learner.clear_learning_data()
        
        print(f"Cleared {deleted} learning records.")
        return 0
        
    except (ImportError, OSError, KeyError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def handle_whitelist_commands(args) -> None:
    """Handle whitelist subcommands
    
    Args:
        args: Parsed arguments with func attribute
    """
    if hasattr(args, 'func') and args.func:
        exit_code = args.func(args)
        sys.exit(exit_code)
    else:
        print("Please specify a whitelist subcommand:")
        print("  User-defined whitelist:")
        print("    add          - Add a tool to user-defined whitelist")
        print("    remove       - Remove a tool from whitelist")
        print("    list         - List all whitelist entries")
        print("    export       - Export whitelist configuration")
        print("    import       - Import whitelist configuration")
        print("    add-prefix   - Add trusted prefix")
        print("    add-category - Add custom category")
        print("  Learning system:")
        print("    suggestions  - View learning suggestions")
        print("    accept       - Accept a suggestion")
        print("    reject       - Reject a suggestion")
        print("    stats        - View learning statistics")
        print("    clear        - Clear all learning data")
        sys.exit(1)


# ============================================
# User-defined whitelist command handlers (NEW)
# ============================================

def handle_whitelist_add(args) -> int:
    """Handle 'whitelist add' command
    
    Args:
        args: Parsed arguments
        
    Returns:
        int: Exit code
    """
    try:
        from .whitelist_loader import WhitelistLoader, UserWhitelistConfig, UserWhitelistCategory
        
        WhitelistLoader(args.workspace_dir)
        
        # Load existing user config or create new one
        if args.level == "workspace":
            directory = os.path.join(args.workspace_dir, "whitelist")
        else:
            directory = SYSTEM_WHITELIST_DIR
        
        user_whitelist_path = os.path.join(directory, USER_WHITELIST_FILE)
        
        if os.path.exists(user_whitelist_path):
            with open(user_whitelist_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            config = UserWhitelistConfig.from_dict(data)
        else:
            config = UserWhitelistConfig(
                created_by="sec-userspace-cli",
                created_at=datetime.now(timezone.utc).isoformat()
            )
        
        # Add tool to category
        if args.category not in config.categories:
            config.categories[args.category] = UserWhitelistCategory(
                name=args.category,
                confidence_boost=args.confidence,
                description=f"Custom category for {args.category}"
            )
        
        category = config.categories[args.category]
        if args.tool not in category.tools:
            category.tools.append(args.tool)
            category.confidence_boost = max(category.confidence_boost, args.confidence)
        
        # Update metadata
        config.updated_at = datetime.now(timezone.utc).isoformat()
        
        # Save configuration
        os.makedirs(directory, exist_ok=True)
        with open(user_whitelist_path, 'w', encoding='utf-8') as f:
            json.dump(config.to_dict(), f, indent=2, ensure_ascii=False)
        
        print(f"Added tool '{args.tool}' to category '{args.category}'")
        print(f"Configuration saved to: {user_whitelist_path}")
        return 0
        
    except (ImportError, OSError, KeyError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def handle_whitelist_remove(args) -> int:
    """Handle 'whitelist remove' command
    
    Args:
        args: Parsed arguments
        
    Returns:
        int: Exit code
    """
    try:
        from .whitelist_loader import WhitelistLoader, USER_WHITELIST_FILE
        
        WhitelistLoader(args.workspace_dir)
        
        if args.level == "workspace":
            directory = os.path.join(args.workspace_dir, "whitelist")
        else:
            directory = SYSTEM_WHITELIST_DIR
        
        user_whitelist_path = os.path.join(directory, USER_WHITELIST_FILE)
        
        if not os.path.exists(user_whitelist_path):
            print(f"No user whitelist found at {user_whitelist_path}")
            return 1
        
        with open(user_whitelist_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        config = UserWhitelistConfig.from_dict(data)
        
        removed_count = 0
        
        # Remove from specified category or all categories
        categories_to_check = [args.category] if args.category else list(config.categories.keys())
        
        for cat_name in categories_to_check:
            if cat_name in config.categories:
                if args.tool in config.categories[cat_name].tools:
                    config.categories[cat_name].tools.remove(args.tool)
                    removed_count += 1
                    
                    # Remove empty categories
                    if not config.categories[cat_name].tools:
                        del config.categories[cat_name]
        
        if removed_count > 0:
            config.updated_at = datetime.now(timezone.utc).isoformat()
            with open(user_whitelist_path, 'w', encoding='utf-8') as f:
                json.dump(config.to_dict(), f, indent=2, ensure_ascii=False)
            print(f"Removed tool '{args.tool}' from {removed_count} category/categories")
        else:
            print(f"Tool '{args.tool}' not found in whitelist")
        
        return 0
        
    except (ImportError, OSError, KeyError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def handle_whitelist_list(args) -> int:
    """Handle 'whitelist list' command
    
    Args:
        args: Parsed arguments
        
    Returns:
        int: Exit code
    """
    try:
        from .whitelist_loader import WhitelistLoader
        
        loader = WhitelistLoader(args.workspace_dir)
        categories = loader.get_categories()
        
        if args.category:
            categories = {k: v for k, v in categories.items() if k == args.category}
        
        if not categories:
            print("No whitelist categories found.")
            return 0
        
        if args.format == "json":
            output = {
                name: {
                    "tools": cat.tools,
                    "confidence_boost": cat.confidence_boost,
                    "description": cat.description
                }
                for name, cat in categories.items()
            }
            print(json.dumps(output, indent=2))
        else:
            print(f"\n{'='*80}")
            print("User-Defined Whitelist Categories")
            print(f"{'='*80}\n")
            
            for name, cat in categories.items():
                print(f"[{name}]")
                print(f"  Description: {cat.description}")
                print(f"  Confidence Boost: {cat.confidence_boost:.1%}")
                print(f"  Tools ({len(cat.tools)}):")
                for tool in cat.tools[:10]:  # Show first 10 tools
                    print(f"    - {tool}")
                if len(cat.tools) > 10:
                    print(f"    ... and {len(cat.tools) - 10} more")
                print()
            
            # Also show trusted prefixes
            prefixes = loader.get_trusted_prefixes()
            if prefixes:
                print(f"\nTrusted Prefixes ({len(prefixes)}):")
                for prefix in prefixes[:5]:
                    print(f"  - {prefix.prefix}: {prefix.reason}")
                if len(prefixes) > 5:
                    print(f"  ... and {len(prefixes) - 5} more")
            
            # Show override rules
            overrides = loader.get_override_rules()
            if overrides:
                print(f"\nOverride Rules ({len(overrides)}):")
                for rule in overrides[:5]:
                    print(f"  - [{rule.id}] {rule.tool_pattern} -> {rule.action}")
                if len(overrides) > 5:
                    print(f"  ... and {len(overrides) - 5} more")
        
        return 0
        
    except (ImportError, OSError, KeyError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def handle_whitelist_export(args) -> int:
    """Handle 'whitelist export' command
    
    Args:
        args: Parsed arguments
        
    Returns:
        int: Exit code
    """
    try:
        from .whitelist_loader import USER_WHITELIST_FILE
        
        if args.level == "workspace":
            directory = os.path.join(args.workspace_dir, "whitelist")
        else:
            directory = SYSTEM_WHITELIST_DIR
        
        user_whitelist_path = os.path.join(directory, USER_WHITELIST_FILE)
        
        if not os.path.exists(user_whitelist_path):
            print(f"No user whitelist found at {user_whitelist_path}")
            return 1
        
        # Read and output the configuration
        with open(user_whitelist_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if args.output:
            os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Exported whitelist to: {args.output}")
        else:
            print(content)
        
        return 0
        
    except (ImportError, OSError, KeyError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def handle_whitelist_import(args) -> int:
    """Handle 'whitelist import' command
    
    Args:
        args: Parsed arguments
        
    Returns:
        int: Exit code
    """
    try:
        from .whitelist_loader import WhitelistLoader, UserWhitelistConfig, USER_WHITELIST_FILE
        
        loader = WhitelistLoader(args.workspace_dir)
        
        # Read input file
        with open(args.input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Validate configuration
        is_valid, error_msg = loader.validate_config(data)
        if not is_valid:
            print(f"Invalid configuration: {error_msg}")
            return 1
        
        if args.level == "workspace":
            directory = os.path.join(args.workspace_dir, "whitelist")
        else:
            directory = SYSTEM_WHITELIST_DIR
        
        user_whitelist_path = os.path.join(directory, USER_WHITELIST_FILE)
        
        if args.merge and os.path.exists(user_whitelist_path):
            # Merge with existing configuration
            with open(user_whitelist_path, 'r', encoding='utf-8') as f:
                existing_data = json.load(f)
            existing_config = UserWhitelistConfig.from_dict(existing_data)
            new_config = UserWhitelistConfig.from_dict(data)
            
            # Merge categories
            for cat_name, category in new_config.categories.items():
                if cat_name in existing_config.categories:
                    # Combine tools
                    existing_tools = set(existing_config.categories[cat_name].tools)
                    existing_tools.update(category.tools)
                    existing_config.categories[cat_name].tools = list(existing_tools)
                else:
                    existing_config.categories[cat_name] = category
            
            # Merge trusted prefixes
            existing_config.trusted_prefixes.extend(new_config.trusted_prefixes)
            
            # Merge override rules
            existing_config.override_rules.extend(new_config.override_rules)
            
            config = existing_config
        else:
            # Replace configuration
            config = UserWhitelistConfig.from_dict(data)
        
        # Save configuration
        os.makedirs(directory, exist_ok=True)
        with open(user_whitelist_path, 'w', encoding='utf-8') as f:
            json.dump(config.to_dict(), f, indent=2, ensure_ascii=False)
        
        print(f"Imported whitelist from: {args.input_file}")
        print(f"Configuration saved to: {user_whitelist_path}")
        return 0
        
    except (ImportError, OSError, KeyError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def handle_whitelist_add_prefix(args) -> int:
    """Handle 'whitelist add-prefix' command
    
    Args:
        args: Parsed arguments
        
    Returns:
        int: Exit code
    """
    try:
        from .whitelist_loader import WhitelistLoader, USER_WHITELIST_FILE, TrustedPrefix
        
        WhitelistLoader(args.workspace_dir)
        
        if args.level == "workspace":
            directory = os.path.join(args.workspace_dir, "whitelist")
        else:
            directory = SYSTEM_WHITELIST_DIR
        
        user_whitelist_path = os.path.join(directory, USER_WHITELIST_FILE)
        
        # Load existing config or create new one
        if os.path.exists(user_whitelist_path):
            with open(user_whitelist_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            config = UserWhitelistConfig.from_dict(data)
        else:
            config = UserWhitelistConfig(
                created_by="sec-userspace-cli",
                created_at=datetime.now(timezone.utc).isoformat()
            )
        
        # Check if prefix already exists
        for prefix in config.trusted_prefixes:
            if prefix.prefix == args.prefix:
                print(f"Prefix '{args.prefix}' already exists in whitelist")
                return 0
        
        # Add new prefix
        config.trusted_prefixes.append(TrustedPrefix(
            prefix=args.prefix,
            reason=args.reason,
            created_by="sec-userspace-cli",
            created_at=datetime.now(timezone.utc).isoformat()
        ))
        
        config.updated_at = datetime.now(timezone.utc).isoformat()
        
        # Save configuration
        os.makedirs(directory, exist_ok=True)
        with open(user_whitelist_path, 'w', encoding='utf-8') as f:
            json.dump(config.to_dict(), f, indent=2, ensure_ascii=False)
        
        print(f"Added trusted prefix '{args.prefix}'")
        print(f"Reason: {args.reason}")
        print(f"Configuration saved to: {user_whitelist_path}")
        return 0
        
    except (ImportError, OSError, KeyError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def handle_whitelist_add_category(args) -> int:
    """Handle 'whitelist add-category' command
    
    Args:
        args: Parsed arguments
        
    Returns:
        int: Exit code
    """
    try:
        from .whitelist_loader import WhitelistLoader, USER_WHITELIST_FILE, UserWhitelistCategory
        
        WhitelistLoader(args.workspace_dir)
        
        if args.level == "workspace":
            directory = os.path.join(args.workspace_dir, "whitelist")
        else:
            directory = SYSTEM_WHITELIST_DIR
        
        user_whitelist_path = os.path.join(directory, USER_WHITELIST_FILE)
        
        # Load existing config or create new one
        if os.path.exists(user_whitelist_path):
            with open(user_whitelist_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            config = UserWhitelistConfig.from_dict(data)
        else:
            config = UserWhitelistConfig(
                created_by="sec-userspace-cli",
                created_at=datetime.now(timezone.utc).isoformat()
            )
        
        # Check if category already exists
        if args.name in config.categories:
            print(f"Category '{args.name}' already exists. Use 'whitelist add' to add tools to it.")
            return 0
        
        # Add new category
        config.categories[args.name] = UserWhitelistCategory(
            name=args.name,
            tools=list(args.tools),
            confidence_boost=args.confidence,
            description=args.description,
            created_by="sec-userspace-cli",
            created_at=datetime.now(timezone.utc).isoformat()
        )
        
        config.updated_at = datetime.now(timezone.utc).isoformat()
        
        # Save configuration
        os.makedirs(directory, exist_ok=True)
        with open(user_whitelist_path, 'w', encoding='utf-8') as f:
            json.dump(config.to_dict(), f, indent=2, ensure_ascii=False)
        
        print(f"Added category '{args.name}' with {len(args.tools)} tools:")
        for tool in args.tools:
            print(f"  - {tool}")
        print(f"Configuration saved to: {user_whitelist_path}")
        return 0
        
    except (ImportError, OSError, KeyError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
