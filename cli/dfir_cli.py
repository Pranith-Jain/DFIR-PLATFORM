import click
import requests
import json
import sys

API_BASE = "http://localhost:8000/api/v1"

@click.group()
def cli():
    """DFIR Platform CLI Tool"""
    pass

@cli.command()
@click.argument('indicator')
def check(indicator):
    """Check IOC reputation"""
    try:
        response = requests.post(f"{API_BASE}/ioc/check", json={"indicator": indicator})
        response.raise_for_status()
        data = response.json()
        
        click.echo(click.style(f"\nResults for: {data['indicator']}", bold=True))
        click.echo(f"Type: {data['type']}")
        
        color = "green"
        if data['verdict'] == "malicious":
            color = "red"
        elif data['verdict'] == "suspicious":
            color = "yellow"
            
        click.echo(f"Verdict: ", nl=False)
        click.echo(click.style(data['verdict'].upper(), fg=color, bold=True))
        click.echo(f"Score: {data['score']}/100")
        
        click.echo("\nSources:")
        for source in data['sources']:
            status = "Clean"
            s_color = "green"
            if source.get('malicious', 0) > 0 or source.get('score', 0) > 50:
                status = "Flagged"
                s_color = "red"
            
            click.echo(f" - {source['provider']}: ", nl=False)
            click.echo(click.style(status, fg=s_color))
            
    except Exception as e:
        click.echo(click.style(f"Error: {str(e)}", fg="red"), err=True)

@cli.command()
@click.argument('domain')
def domain(domain):
    """Perform domain security check"""
    try:
        response = requests.post(f"{API_BASE}/domain/check", json={"domain": domain})
        response.raise_for_status()
        data = response.json()
        
        click.echo(click.style(f"\nSecurity Check for: {data['domain']}", bold=True))
        click.echo(f"Health Score: {data['health_score']}")
        click.echo(f"Verdict: {data['verdict'].upper()}")
        
        click.echo("\nDNS Records:")
        for rtype, records in data['dns'].items():
            if records:
                click.echo(f" {rtype}: {', '.join(records[:3])}{'...' if len(records) > 3 else ''}")
                
        click.echo("\nEmail Security:")
        click.echo(f" SPF: {'✅' if data['spf']['found'] else '❌'}")
        click.echo(f" DMARC: {'✅' if data['dmarc']['found'] else '❌'}")
        
        if data['ssl']['valid']:
            click.echo(f" SSL: ✅ Valid (Issuer: {data['ssl']['issuer'].get('commonName', 'Unknown')})")
        else:
            click.echo(f" SSL: ❌ Invalid/Missing")
            
    except Exception as e:
        click.echo(click.style(f"Error: {str(e)}", fg="red"), err=True)

@cli.command()
@click.argument('domain')
def scan(domain):
    """Perform exposure scan (subdomains, ports)"""
    click.echo(f"Scanning {domain} (this may take a minute)...")
    try:
        response = requests.post(f"{API_BASE}/exposure/scan", json={"domain": domain})
        response.raise_for_status()
        data = response.json()
        
        click.echo(click.style(f"\nExposure Scan for: {data['domain']}", bold=True))
        click.echo(f"Attack Surface Score: {data['attack_surface_score'].upper()}")
        
        click.echo(f"\nSubdomains found: {len(data['subdomains'])}")
        for sub in data['subdomains'][:10]:
            click.echo(f" - {sub}")
        if len(data['subdomains']) > 10:
            click.echo(f" ... and {len(data['subdomains']) - 10} more")
            
        click.echo(f"\nOpen Ports: {data['open_ports']['open_count']}")
        for port in data['open_ports']['open']:
            click.echo(f" - {port['port']}/{port['service']}")
            
    except Exception as e:
        click.echo(click.style(f"Error: {str(e)}", fg="red"), err=True)

if __name__ == '__main__':
    cli()
