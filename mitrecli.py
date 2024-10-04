import requests
from rich.console import Console
from rich.table import Table
import pyfiglet  # Import the pyfiglet library for ASCII art
from rich.panel import Panel  # Import Panel for better UI framing

# Console object to print rich text
console = Console()

# URLs for Enterprise and Mobile ATT&CK data
enterprise_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
mobile_url = "https://raw.githubusercontent.com/mitre/cti/refs/heads/master/mobile-attack/mobile-attack.json"

# Base URL for MITRE ATT&CK Techniques (for linking)
mitre_attack_base_url = "https://attack.mitre.org/techniques/"

# Function to fetch MITRE ATT&CK data (Enterprise or Mobile)
def fetch_mitre_attack_data(source='enterprise'):
    url = enterprise_url if source == 'enterprise' else mobile_url
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        console.print(f"Failed to fetch MITRE ATT&CK {source.capitalize()} data from GitHub.", style="bold red")
        return None

# Function to display tactics and techniques (supports both Enterprise and Mobile ATT&CK)
def display_tactics(search_term=None, filter_tactic=None, sort_by=None, source='enterprise'):
    console.print(Panel.fit(f"Fetching MITRE ATT&CK {source.capitalize()} tactics and techniques...", style="bold green"))
    data = fetch_mitre_attack_data(source)

    if data:
        techniques = []

        for item in data["objects"]:
            if item["type"] == "attack-pattern":
                technique_id = item["external_references"][0]["external_id"]
                technique_name = item["name"]

                # Safe access to tactic name
                tactic_name = "N/A"
                if "kill_chain_phases" in item and item["kill_chain_phases"]:
                    tactic_name = item["kill_chain_phases"][0].get("phase", "N/A")

                description = item.get("description", "No description available")

                # Shorten the description to 100 characters
                max_description_length = 100
                if len(description) > max_description_length:
                    description = description[:max_description_length] + "..."

                technique_url = mitre_attack_base_url + technique_id

                # Format the description and link, separating them by a new line
                formatted_description = f"{description}\n\n[Link]({technique_url})"

                # Search functionality
                if (search_term is None or search_term.lower() in technique_name.lower() or search_term.lower() in technique_id.lower()) and \
                   (filter_tactic is None or filter_tactic.lower() in tactic_name.lower()):
                    techniques.append((technique_id, technique_name, tactic_name, formatted_description))

        # Sort techniques if specified
        if sort_by == 'tactic':
            techniques.sort(key=lambda x: x[2])  # Sort by tactic name

        # Display table
        table = Table(title=f"MITRE ATT&CK {source.capitalize()} Techniques", show_header=True, header_style="bold cyan", border_style="bold blue", padding=(0, 1))
        table.add_column("Technique ID", justify="right", style="bold cyan", no_wrap=True)
        table.add_column("Technique Name", style="bold magenta")
        table.add_column("Tactic", style="bold yellow")
        table.add_column("Description & Link", style="bold green")

        for tech in techniques:
            table.add_row(tech[0], tech[1], tech[2], tech[3])
            # Add a full-width horizontal separator line
            table.add_row(*["-" * 10, "-" * 10, "-" * 10, "-" * 10])  # Adjust the number of characters to match your columns

        console.print(Panel(table, title="Tactics & Techniques", title_align="left", border_style="bright_green"))

# Function to display APT groups (only available in Enterprise ATT&CK)
def display_apt_groups(search_term=None):
    console.print(Panel.fit("Fetching MITRE ATT&CK APT groups...", style="bold green"))
    data = fetch_mitre_attack_data('enterprise')

    if data:
        apt_groups = []

        for item in data["objects"]:
            if item["type"] == "intrusion-set":
                group_id = item["external_references"][0]["external_id"]
                group_name = item["name"]
                description = item.get("description", "No description available")

                # Shorten the description to a reasonable length for display
                max_description_length = 80
                if len(description) > max_description_length:
                    description = description[:max_description_length] + "..."  # Truncate description

                # Search functionality
                if search_term is None or search_term.lower() in group_name.lower() or search_term.lower() in group_id.lower():
                    apt_groups.append((group_id, group_name, description))

        # Display table with better formatting
        apt_table = Table(title="MITRE ATT&CK APT Groups", show_header=True, header_style="bold cyan", border_style="bold blue", padding=(0, 1))
        apt_table.add_column("Group ID", justify="right", style="bold cyan", no_wrap=True)
        apt_table.add_column("Group Name", style="bold magenta")
        apt_table.add_column("Description", style="bold green")
        apt_table.add_column("Link", justify="right", style="bold blue")

        for group in apt_groups:
            # Format the description to have the link at the end
            link = f"[Link](https://attack.mitre.org/groups/{group[0]})"
            apt_table.add_row(group[0], group[1], group[2], link)

        console.print(Panel(apt_table, title="APT Groups", title_align="left", border_style="bright_green"))

# Function to view details of a specific technique (supports both Enterprise and Mobile ATT&CK)
def view_technique_details(technique_id, source='enterprise'):
    console.print(Panel.fit(f"Fetching details for Technique ID: {technique_id}", style="bold green"))
    data = fetch_mitre_attack_data(source)

    if data:
        for item in data["objects"]:
            if item["type"] == "attack-pattern" and item["external_references"][0]["external_id"] == technique_id:
                console.print(Panel.fit("Technique Details", style="bold blue"))
                console.print(f"[bold cyan]ID:[/bold cyan] {item['external_references'][0]['external_id']}")
                console.print(f"[bold cyan]Name:[/bold cyan] {item['name']}")
                console.print(f"[bold cyan]Description:[/bold cyan] {item.get('description', 'No description available')}")

                # Safely handle kill chain phases
                kill_chain_phases = item.get("kill_chain_phases", [])
                phases = [phase.get("phase", "N/A") for phase in kill_chain_phases]
                console.print(f"[bold cyan]Kill Chain Phases:[/bold cyan] {', '.join(phases) if phases else 'None'}")

                technique_url = mitre_attack_base_url + technique_id
                console.print(f"[bold cyan]Link:[/bold cyan] {technique_url}")

                return
        console.print("[bold red]Technique ID not found.[/bold red]")

# Function to display the menu and handle user input
def menu():
    # Display ASCII art for the title
    ascii_art = pyfiglet.figlet_format("MITRE ATTACK CLI", font="slant")
    console.print(Panel(ascii_art, title="MITRE ATT&CK Learning Tool", title_align="center", border_style="bold yellow"))  # Print the ASCII art in a Panel with yellow border

    while True:
        console.print("--- MITRE ATT&CK Learning Tool Menu ---", style="bold blue")
        console.print("[bold yellow]1.[/bold yellow] Explore MITRE ATT&CK Tactics and Techniques (Enterprise)")
        console.print("[bold yellow]2.[/bold yellow] Explore MITRE ATT&CK Tactics and Techniques (Mobile)")
        console.print("[bold yellow]3.[/bold yellow] Explore MITRE ATT&CK APT Groups (Enterprise only)")
        console.print("[bold yellow]4.[/bold yellow] View Details of a Technique by ID (Enterprise or Mobile)")
        console.print("[bold yellow]5.[/bold yellow] Exit")
        choice = input("Please select an option (1-5): ")

        if choice == '1':
            search_term = input("Enter search term (or leave blank): ") or None
            filter_tactic = input("Enter tactic to filter by (or leave blank): ") or None
            sort_by = input("Sort by tactic? (yes/no): ").strip().lower() == 'yes'
            display_tactics(search_term, filter_tactic, 'tactic' if sort_by else None, source='enterprise')

        elif choice == '2':
            search_term = input("Enter search term (or leave blank): ") or None
            filter_tactic = input("Enter tactic to filter by (or leave blank): ") or None
            sort_by = input("Sort by tactic? (yes/no): ").strip().lower() == 'yes'
            display_tactics(search_term, filter_tactic, 'tactic' if sort_by else None, source='mobile')

        elif choice == '3':
            search_term = input("Enter search term for APT groups (or leave blank): ") or None
            display_apt_groups(search_term)

        elif choice == '4':
            technique_id = input("Enter Technique ID (e.g., TXXXX): ").strip()
            source = input("Enter source (enterprise/mobile): ").strip().lower()
            view_technique_details(technique_id, source=source)

        elif choice == '5':
            console.print("Exiting the MITRE ATT&CK Learning Tool. Goodbye!", style="bold red")
            break
        else:
            console.print("[bold red]Invalid choice! Please select a valid option.[/bold red]")

if __name__ == "__main__":
    menu()
