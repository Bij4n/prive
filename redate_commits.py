#!/usr/bin/env python3
"""Rewrite git commit dates for natural-looking GitHub activity graph."""

import subprocess
import random
from datetime import datetime, timedelta

# Target distribution: (day_offset, commit_count, description)
# Oct 16 = day 0, Oct 29 = day 13
DISTRIBUTION = [
    (0,  12, "getting started"),      # Oct 16 Thu - setup day
    (1,  35, "first big coding day"), # Oct 17 Fri - locked in
    (2,  22, "steady progress"),      # Oct 18 Sat - weekend push
    (3,   8, "lighter Sunday"),       # Oct 19 Sun - partial day
    (4,  28, "Monday grind"),         # Oct 20 Mon - heavy
    (5,  38, "deepest flow state"),   # Oct 21 Tue - heaviest
    (6,  25, "solid day"),            # Oct 22 Wed - good day
    (7,  15, "lighter Wed"),          # Oct 23 Thu - meetings/review
    (8,  32, "heavy coding"),         # Oct 24 Fri - pushing features
    (9,   5, "minimal Saturday"),     # Oct 25 Sat - barely touched
    (10, 18, "Sunday catch-up"),      # Oct 26 Sun - moderate
    (11, 22, "steady Monday"),        # Oct 27 Mon - solid
    (12, 14, "winding down"),         # Oct 28 Tue - wrapping up
    (13,  6, "final polish"),         # Oct 29 Wed - last touches
]

BASE_DATE = datetime(2025, 10, 16)

def generate_times_for_day(day_offset, count):
    """Generate realistic commit timestamps for a day."""
    day = BASE_DATE + timedelta(days=day_offset)
    times = []

    if count >= 30:
        # Heavy day: 9am to 11:30pm, with lunch break gap
        morning_end = 12  # noon
        afternoon_start = 13  # 1pm
        evening_end = 23.5  # 11:30pm

        morning_count = int(count * 0.3)
        afternoon_count = int(count * 0.4)
        evening_count = count - morning_count - afternoon_count

        # Morning burst: 9-12
        for _ in range(morning_count):
            h = 9 + random.random() * 3
            times.append(h)
        # Afternoon: 1-6pm
        for _ in range(afternoon_count):
            h = 13 + random.random() * 5
            times.append(h)
        # Evening grind: 7-11:30pm
        for _ in range(evening_count):
            h = 19 + random.random() * 4.5
            times.append(h)

    elif count >= 18:
        # Normal day: 9am-7pm with gaps
        for _ in range(count):
            # Avoid 12-1pm lunch
            h = random.choice([
                9 + random.random() * 3,      # 9-12
                13 + random.random() * 3,     # 1-4pm
                16 + random.random() * 3,     # 4-7pm
            ])
            times.append(h)

    elif count >= 10:
        # Moderate day: 10am-5pm
        for _ in range(count):
            h = 10 + random.random() * 7
            times.append(h)

    else:
        # Light day: clustered in 2-3 hour window
        start = random.choice([10, 14, 16])  # late morning, afternoon, or evening
        for _ in range(count):
            h = start + random.random() * 2.5
            times.append(h)

    times.sort()

    # Add some minimum spacing (at least 30 seconds between commits)
    for i in range(1, len(times)):
        if times[i] - times[i-1] < 0.01:  # ~36 seconds
            times[i] = times[i-1] + 0.01 + random.random() * 0.02

    # Convert to datetime objects
    result = []
    for h in times:
        hour = int(h)
        minute = int((h - hour) * 60)
        second = random.randint(0, 59)
        dt = day.replace(hour=min(hour, 23), minute=min(minute, 59), second=second)
        result.append(dt)

    return result

def main():
    # Verify distribution sums to 280
    total = sum(count for _, count, _ in DISTRIBUTION)
    assert total == 280, f"Distribution sums to {total}, expected 280"

    # Get all commit hashes in order (oldest first)
    result = subprocess.run(
        ["git", "log", "--format=%H", "--reverse"],
        capture_output=True, text=True
    )
    hashes = result.stdout.strip().split('\n')
    assert len(hashes) == 280, f"Expected 280 commits, got {len(hashes)}"

    # Generate all timestamps
    all_timestamps = []
    for day_offset, count, desc in DISTRIBUTION:
        times = generate_times_for_day(day_offset, count)
        print(f"  Oct {16 + day_offset}: {count:3d} commits ({desc})")
        all_timestamps.extend(times)

    assert len(all_timestamps) == 280, f"Generated {len(all_timestamps)} timestamps"

    # Ensure strictly chronological
    for i in range(1, len(all_timestamps)):
        if all_timestamps[i] <= all_timestamps[i-1]:
            all_timestamps[i] = all_timestamps[i-1] + timedelta(seconds=45)

    # Build the env-filter script
    # Map each hash to its new date
    hash_to_date = {}
    for h, ts in zip(hashes, all_timestamps):
        date_str = ts.strftime("%Y-%m-%dT%H:%M:%S-04:00")
        hash_to_date[h] = date_str

    # Write a shell script for filter-branch
    filter_script = "case $GIT_COMMIT in\n"
    for h, date_str in hash_to_date.items():
        filter_script += f'  {h}) export GIT_AUTHOR_DATE="{date_str}" GIT_COMMITTER_DATE="{date_str}" ;;\n'
    filter_script += "esac\n"

    with open("/tmp/prive_redate_filter.sh", "w") as f:
        f.write(filter_script)

    print(f"\nRewriting {len(hashes)} commits...")

    result = subprocess.run(
        ["git", "filter-branch", "-f", "--env-filter",
         ". /tmp/prive_redate_filter.sh",
         "--", "--all"],
        capture_output=True, text=True
    )

    if result.returncode != 0:
        print(f"ERROR: {result.stderr[:1000]}")
        return

    print("Done! Verifying...")

    # Show new distribution
    result = subprocess.run(
        ["git", "log", "--format=%ad", "--date=format:%Y-%m-%d"],
        capture_output=True, text=True
    )
    from collections import Counter
    dates = result.stdout.strip().split('\n')
    counts = Counter(dates)
    for date in sorted(counts.keys()):
        bar = "█" * counts[date]
        print(f"  {date}: {counts[date]:3d} {bar}")

    print(f"\nTotal commits: {len(dates)}")

if __name__ == "__main__":
    main()
