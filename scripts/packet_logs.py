import json
import re
from datetime import datetime
from collections import defaultdict
import pandas as pd
import matplotlib.pyplot as plt
from reportlab.lib.pagesizes import LETTER, landscape
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    Spacer,
    Image,
    PageBreak,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import os

def parse_packet_id(packet_id):
    """
    Parses the packet ID into its components.
    Format: {Source IP}:{Source Port}->{Destination IP}:{Destination Port}:{Sequence Number}
    """
    pattern = r"(\d+):(\d+)->(\d+):(\d+):(\d+)"
    match = re.match(pattern, packet_id)
    if match:
        src_ip_int = int(match.group(1))
        src_port = int(match.group(2))
        dest_ip_int = int(match.group(3))
        dest_port = int(match.group(4))
        seq_num = int(match.group(5))

        src_ip = int_to_ip(src_ip_int)
        dest_ip = int_to_ip(dest_ip_int)

        return {
            "Source IP": src_ip,
            "Source Port": src_port,
            "Destination IP": dest_ip,
            "Destination Port": dest_port,
            "Sequence Number": seq_num,
        }
    else:
        return None

def int_to_ip(ip_int):
    """
    Converts a 32-bit integer to a dotted-decimal IP string.
    """
    return ".".join([str((ip_int >> (i * 8)) & 0xFF) for i in reversed(range(4))])

def read_json_logs(input_file):
    """
    Reads multiple JSON objects from a single file using a streaming approach.
    """
    decoder = json.JSONDecoder()
    json_objects = []
    with open(input_file, 'r') as f:
        content = f.read()
    pos = 0
    while pos < len(content):
        try:
            obj, index = decoder.raw_decode(content, pos)
            json_objects.append(obj)
            pos = index
            # Skip any whitespace or separators
            while pos < len(content) and content[pos].isspace():
                pos += 1
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON at position {pos}: {e}")
            break
    return json_objects

def process_logs(json_objects):
    """
    Processes the list of JSON objects and organizes them into a dictionary.
    Each Packet ID maps to its sent and received entries.
    """
    packets = defaultdict(dict)

    for json_obj in json_objects:
        if not isinstance(json_obj, dict):
            print("Skipping non-dict JSON object")
            continue
        for packet_id, details in json_obj.items():
            if not isinstance(details, dict):
                print(f"Skipping non-dict details for Packet ID {packet_id}")
                continue

            if packet_id not in packets:
                packets[packet_id] = {"sent": None, "received": None}

            status = details.get("status", "").lower()
            timestamp_str = details.get("timestamp", "")
            flags = details.get("flags", [])
            options = details.get("options", [])

            # Parse timestamp
            try:
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                print(f"Invalid timestamp format for Packet ID {packet_id}: {timestamp_str}")
                timestamp = None

            # Assign details based on status
            if status == "sent":
                packets[packet_id]["sent"] = {
                    "timestamp": timestamp,
                    "flags": flags,
                    "options": options,
                }
            elif status == "received":
                packets[packet_id]["received"] = {
                    "timestamp": timestamp,
                    "flags": flags,
                    "options": options,
                }
            else:
                print(f"Unknown status '{status}' for Packet ID {packet_id}")

    return packets

def compute_time_differences(packets):
    """
    For each Packet ID, compute the time difference between sent and received.
    """
    data_rows = []
    for packet_id, statuses in packets.items():
        parsed_id = parse_packet_id(packet_id)
        if not parsed_id:
            print(f"Skipping invalid Packet ID format: {packet_id}")
            continue

        sent = statuses.get("sent")
        received = statuses.get("received")

        # Initialize fields
        sent_time = received_time = time_diff = None
        flags_sent = options_sent = flags_received = options_received = ""

        if sent:
            sent_time = sent["timestamp"]
            flags_sent = "; ".join(sent["flags"])
            options_sent = "; ".join(sent["options"])

        if received:
            received_time = received["timestamp"]
            flags_received = "; ".join(received["flags"])
            options_received = "; ".join(received["options"])

        if sent_time and received_time:
            time_diff = (sent_time - received_time).total_seconds()
            # Convert to positive value
            time_diff = abs(time_diff)
        else:
            time_diff = None

        data_rows.append({
            "Packet ID": packet_id,
            "Source IP": parsed_id["Source IP"],
            "Source Port": parsed_id["Source Port"],
            "Destination IP": parsed_id["Destination IP"],
            "Destination Port": parsed_id["Destination Port"],
            "Sequence Number": parsed_id["Sequence Number"],
            "Sent Timestamp": sent_time.strftime("%Y-%m-%d %H:%M:%S") if sent_time else "",
            "Received Timestamp": received_time.strftime("%Y-%m-%d %H:%M:%S") if received_time else "",
            "Time Diff (s)": f"{time_diff:.2f}" if time_diff is not None else "",
            "Flags Sent": flags_sent,
            "Options Sent": options_sent,
            "Flags Received": flags_received,
            "Options Received": options_received,
        })

    return data_rows

def generate_pdf_report(data_rows, output_pdf):
    """
    Generates a PDF report from the data rows, splitting the table into two sets of columns across two pages.
    """
    # Convert to DataFrame for easier manipulation
    df = pd.DataFrame(data_rows)

    if df.empty:
        print("No data available to generate the PDF report.")
        return

    # Create visualizations
    create_flag_chart(df, "flags_chart.png")
    create_option_chart(df, "options_chart.png")

    # Define custom styles
    styles = getSampleStyleSheet()
    styleN = styles['Normal']
    styleBH = styles['Heading2']

    # Create a custom Paragraph style for table cells
    table_cell_style = ParagraphStyle(
        'table_cell',
        parent=styles['Normal'],
        fontSize=6,  # Smaller font size
        leading=7,    # Line height
    )

    # Split the columns into two groups
    all_columns = [
        "Packet ID",
        "Source IP",
        "Source Port",
        "Destination IP",
        "Destination Port",
        "Sequence Number",
        "Sent Timestamp",
        "Received Timestamp",
        "Time Diff (s)",
        "Flags Sent",
        "Options Sent",
        "Flags Received",
        "Options Received",
    ]

    # Define how to split the columns. For better context, include 'Packet ID' in both tables.
    first_table_columns = [
        "Packet ID",
        "Source IP",
        "Source Port",
        "Destination IP",
        "Destination Port",
        "Sequence Number",
    ]

    second_table_columns = [
        "Packet ID",
        "Sent Timestamp",
        "Received Timestamp",
        "Time Diff (s)",
        "Flags Sent",
        "Options Sent",
        "Flags Received",
        "Options Received",
    ]

    # Convert DataFrame to list of lists with Paragraphs for wrapping
    def prepare_table_data(columns):
        table_data = []
        # Header with abbreviated column names if needed
        header = columns
        table_data.append(header)

        for index, row in df.iterrows():
            row_data = []
            for col in columns:
                item = row[col]
                if isinstance(item, str) and '; ' in item:
                    # If the cell contains multiple items, wrap them
                    para = Paragraph(item.replace('; ', '<br/>'), table_cell_style)
                else:
                    para = Paragraph(str(item), table_cell_style)
                row_data.append(para)
            table_data.append(row_data)
        return table_data

    first_table_data = prepare_table_data(first_table_columns)
    second_table_data = prepare_table_data(second_table_columns)

    # Define column widths (in points). Adjust as necessary.
    # Total page width in landscape LETTER: 792 points
    # Subtracting margins: 20 (left) + 20 (right) = 40 points
    # Available width: 752 points

    # First table column widths
    first_column_widths = [
        100,  # Packet ID
        60,   # Source IP
        50,   # Source Port
        60,   # Destination IP
        50,   # Destination Port
        70,   # Sequence Number
    ]

    # Second table column widths
    second_column_widths = [
        100,  # Packet ID
        80,   # Sent Timestamp
        80,   # Received Timestamp
        60,   # Time Diff (s)
        80,   # Flags Sent
        100,  # Options Sent
        80,   # Flags Received
        100,  # Options Received
    ]

    # Create a function to generate a table
    def create_table(data, column_widths):
        table = Table(data, colWidths=column_widths, repeatRows=1)
        # Define Table Style
        table_style = TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.darkblue),
            ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),

            ('ALIGN',(0,0),(-1,-1),'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 7),

            ('BOTTOMPADDING', (0,0), (-1,0), 6),
            ('BACKGROUND',(0,1),(-1,-1),colors.whitesmoke),

            ('GRID', (0,0), (-1,-1), 0.25, colors.grey),
        ])

        # Apply alternating row colors
        for i in range(1, len(data)):
            if i % 2 == 0:
                bg_color = colors.lightgrey
            else:
                bg_color = colors.whitesmoke
            table_style.add('BACKGROUND', (0,i), (-1,i), bg_color)

        table.setStyle(table_style)
        return table

    # Create first and second tables
    table1 = create_table(first_table_data, first_column_widths)
    table2 = create_table(second_table_data, second_column_widths)

    # Create PDF
    doc = SimpleDocTemplate(
        output_pdf,
        pagesize=landscape(LETTER),
        rightMargin=20,
        leftMargin=20,
        topMargin=20,
        bottomMargin=20,
    )
    elements = []
    title = Paragraph("TCP Packet Log Report", styles['Title'])
    elements.append(title)
    elements.append(Spacer(1, 12))

    # Add first table
    elements.append(table1)
    elements.append(Spacer(1, 12))

    # Add a page break
    elements.append(PageBreak())

    # Add second table
    elements.append(table2)
    elements.append(Spacer(1, 12))

    # Add Visualizations (optional: can be on the first or second page)
    # Here, adding them to the second page
    if os.path.exists("flags_chart.png"):
        elements.append(Paragraph("TCP Flags Distribution", styles['Heading2']))
        elements.append(Image("flags_chart.png", width=6*inch, height=3*inch))
        elements.append(Spacer(1, 12))
    if os.path.exists("options_chart.png"):
        elements.append(Paragraph("TCP Options Distribution", styles['Heading2']))
        elements.append(Image("options_chart.png", width=6*inch, height=3*inch))
        elements.append(Spacer(1, 12))

    # Build PDF
    doc.build(elements)

    # Remove temporary chart images
    if os.path.exists("flags_chart.png"):
        os.remove("flags_chart.png")
    if os.path.exists("options_chart.png"):
        os.remove("options_chart.png")

    print(f"PDF report generated: {output_pdf}")

def create_flag_chart(df, output_image):
    """
    Creates a bar chart for TCP flags distribution.
    """
    flags = df["Flags Sent"].dropna().str.split("; ").explode().tolist() + \
            df["Flags Received"].dropna().str.split("; ").explode().tolist()
    if not flags:
        print("No flags to plot.")
        return
    flag_counts = pd.Series(flags).value_counts()

    plt.figure(figsize=(10,6))
    flag_counts.plot(kind='bar', color='skyblue')
    plt.title('TCP Flags Distribution')
    plt.xlabel('Flags')
    plt.ylabel('Frequency')
    plt.tight_layout()
    plt.savefig(output_image)
    plt.close()

def create_option_chart(df, output_image):
    """
    Creates a bar chart for TCP options distribution.
    """
    options = df["Options Sent"].dropna().str.split("; ").explode().tolist() + \
              df["Options Received"].dropna().str.split("; ").explode().tolist()
    if not options:
        print("No options to plot.")
        return
    option_counts = pd.Series(options).value_counts()

    plt.figure(figsize=(12,6))
    option_counts.plot(kind='bar', color='salmon')
    plt.title('TCP Options Distribution')
    plt.xlabel('Options')
    plt.ylabel('Frequency')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(output_image)
    plt.close()

def main():
    input_log_file = '/local/research/research-mitmproxy/build/packet_log.json'   # Replace with your actual log file path
    output_pdf = 'TCP_Packet_Log_Report.pdf'

    # Read and parse JSON logs
    json_objects = read_json_logs(input_log_file)
    packets = process_logs(json_objects)

    # Compute time differences and prepare data rows
    data_rows = compute_time_differences(packets)

    # Generate PDF report
    generate_pdf_report(data_rows, output_pdf)

if __name__ == "__main__":
    main()