from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import Paragraph, Image
import xlwt
from reportlab.lib.colors import Color

from finance_and_corporate_team.models import BudgetSheetSignature
from insb_port import settings
from main_website.models import Toolkit

class BudgetPDF:

    def create_pdf(sc_ag_primary, title, cost_data, revenue_data, show_usd_rates):
        # Create a BytesIO buffer to hold the PDF data
        buffer = BytesIO()

        c = canvas.Canvas(buffer, pagesize=A4)
        width, height = A4

        branch_logo = Toolkit.objects.get(title=BudgetPDF.get_sc_ag_logo_name(1)).picture
        branch_logo_path = settings.MEDIA_ROOT+str(branch_logo)
        sc_ag_logo_path = None

        if sc_ag_primary == 1:
            # # Watermark Logo (Behind the Text)
            # c.setFillAlpha(0.15)  # Make watermark logo faint
            # c.drawImage(branch_logo_path, 60, 230, width=470, height=470, mask='auto')
            pass
        else:
            sc_ag_logo = Toolkit.objects.get(title=BudgetPDF.get_sc_ag_logo_name(sc_ag_primary)).picture
            sc_ag_logo_path = settings.MEDIA_ROOT+str(sc_ag_logo)
            # Watermark Logo (Behind the Text)
            c.setFillAlpha(0.15)  # Make watermark logo faint
            c.drawImage(sc_ag_logo_path, 70, 230, width=470, height=470, mask='auto')
        
        # Top Left Logo
        c.setFillAlpha(1)  # Ensure logos are fully opaque
        c.drawImage(branch_logo_path, 50, height - 80, width=50, height=50, mask='auto')

        if sc_ag_primary != 1:
            # Top Right Logo
            c.drawImage(sc_ag_logo_path, width - 90, height - 80, width=50, height=50, mask='auto')

        # Title
        # c.setFont("Helvetica-Bold", 16)
        style = getSampleStyleSheet()["Normal"]
        style = ParagraphStyle(style, leading=17, fontName='Helvetica-Bold', fontSize=16, alignment=1)

        # Create a Paragraph with the given text
        para = Paragraph(title, style)

        # Wrap the text to fit within max_width
        text_width = min(500, width - 20)  # Limit width
        wrapped_width, wrapped_height = para.wrap(text_width, 0)  # Get required height

        # Adjust Y so the first line stays in place
        adjusted_y_position = height - 100 - wrapped_height  # Shift down

        # Center X calculation
        x_position = (width - wrapped_width) / 2

        # Draw the wrapped text
        para.drawOn(c, x_position, adjusted_y_position)

        # c.drawCentredString(width / 2, height - 90, title)
        c.setTitle(title)

        # Cost Breakdown (First)
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, adjusted_y_position - 40, "Cost Breakdown")

        cost_header = {-1 : ["Item", "Quantity", ("Price / Unit (BDT)" if show_usd_rates == False else "Price / Unit (USD)"), ("Total Price (BDT)" if show_usd_rates == False else "Total Price (USD)")]}
        cost_header.update(cost_data)
        # Draw cost table and get final Y position
        new_y = BudgetPDF.draw_table(c, cost_header, x=50, y=adjusted_y_position - 55, col_widths=[180, 65, 115, 140], primary=sc_ag_primary)

        # Revenue Breakdown (Positioned Below Cost Breakdown)
        c.setFont("Helvetica-Bold", 12)
        revenue_y = new_y - 30  # Provide extra space
        c.drawString(50, revenue_y, "Total Revenue")

        revenue_header = {-1 : ["Revenue Type", "Quantity", ("Revenue / Unit (BDT)" if show_usd_rates == False else "Revenue / Unit (USD)"), ("Revenue Generated (BDT)" if show_usd_rates == False else "Revenue Generated (USD)")]}
        revenue_header.update(revenue_data)
        BudgetPDF.draw_table(c, revenue_header, x=50, y=revenue_y - 15, col_widths=[170, 65, 115, 150], primary=sc_ag_primary)


        signatures = BudgetSheetSignature.objects.filter(sc_ag__primary=sc_ag_primary)

        if signatures.exists():
            # Signatures
            c.line(50, 75, 250, 75)
            c.line(350, 75, 510, 75)

            c.setFont("Times-Roman", 12)

            y = 60
            for line in signatures[0].left_signature.splitlines():
                c.drawString(50, y, line)
                y -= 15

            y = 60
            for line in signatures[0].right_signature.splitlines():
                c.drawString(350, y, line)
                y -= 15

        # Save the PDF
        c.save()

        # Move buffer cursor to the beginning
        buffer.seek(0)

        return buffer

    def draw_table(canvas, data, x, y, col_widths, primary):

        styles = getSampleStyleSheet()  

        fontSize = 11
        # Convert long text cells to Paragraph objects for wrapping
        wrapped_data = []
        for i, row in enumerate(data.values()):
            if i == 0:
                # Bold style for the first row
                style = ParagraphStyle(name="Header", parent=styles["Normal"], fontName='Helvetica-Bold', alignment=1, textColor=colors.white, leading=18)

            else:
                # Default style for normal text
                style = ParagraphStyle(name="Normal", parent=styles["Normal"], fontName='Helvetica', alignment=1, fontSize=fontSize)

            wrapped_row = []
            for j in range(len(row)):
                if j == 0 and i == 0:
                    wrapped_row.append(Paragraph(str(row[j]), ParagraphStyle(name="Normal", parent=styles["Normal"], fontName='Helvetica-Bold', alignment=0, textColor=colors.white, leading=18)))
                elif j == 0:
                    wrapped_row.append(Paragraph(str(row[j]), ParagraphStyle(name="Normal", parent=styles["Normal"], fontName='Helvetica', alignment=0, fontSize=fontSize, leading=fontSize+2)))
                else:
                    wrapped_row.append(Paragraph(str(row[j]), style))

            wrapped_data.append(wrapped_row)

        # **Calculate Totals (assuming numerical columns except first)**
        total_row = []
        total_row.append(Paragraph("Total", ParagraphStyle(name="Total", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=fontSize, leading=fontSize+5)))

        for col_idx in range(1, len(wrapped_data[0])):  # Skip first column
            try:
                if col_idx == 3:
                    total_value = sum(float(row[col_idx].text) for row in wrapped_data[1:] if row[col_idx].text.replace('.', '', 1).isdigit())
                else:
                    total_value = ''
            except ValueError:
                total_value = "--"  # Non-numeric column

            total_row.append(Paragraph(str(total_value), ParagraphStyle(name="Total", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=fontSize, leading=fontSize+5)))

        wrapped_data.append(total_row)  # Append total row

        table_style = TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BudgetPDF.get_sc_ag_header_color(primary)),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
            ("TOPPADDING", (0, 0), (-1, 0), 10),
            # ("GRID", (0, 0), (-1, -1), 1, colors.black),
            # Remove INNER grid lines for the total row
            ("LINEABOVE", (0, -1), (-1, -1), 1, colors.black),  # Add a line above the total row
            # ("LINEBELOW", (0, -1), (-1, -1), 1, colors.black),  # Keep bottom border for total row
            ("LINEBEFORE", (0, -1), (0, -1), 1, colors.black),  # Left outer border
            ("LINEBEFORE", (-1, -1), (-1, -1), 1, colors.black),  # Left outer border
            # ("LINEAFTER", (-1, -1), (-1, -1), 1, colors.black),  # Right outer border
            # ("GRID", (0, 0), (-1, -2), 1, colors.black),  # Keep grid for all except last row
        ])
        table = Table(wrapped_data, colWidths=col_widths)

        table_width, table_height = table.wrapOn(canvas, 0, 0)
        table.setStyle(table_style)

        # # Draw semi-transparent beige rectangles behind data rows (excluding header and total)
        # row_heights = table._rowHeights
        # for row_index in range(1, len(wrapped_data)):  # skip header
        #     row_y = y - sum(row_heights[:row_index])
        #     row_height = row_heights[row_index]

        #     canvas.saveState()
        #     canvas.setFillAlpha(0.3)
        #     canvas.setFillColor(Color(0.96, 0.96, 0.86, 0.5))  # beige
        #     canvas.rect(x, row_y - row_height, table_width, row_height, stroke=0, fill=1)
        #     canvas.restoreState()
        table.drawOn(canvas, x, y - table_height)

        # Return new Y position after drawing the table
        return y - table_height - 15  # Adding extra spacing

    def export_budget_sheet_to_excel(sc_ag_primary, title, cost_data, revenue_data, total_cost, total_revenue):

        # Create a workbook and add a worksheet
        wb = xlwt.Workbook()
        ws = wb.add_sheet("Budget Sheet")

        # Define styles
        title_style = xlwt.easyxf(
            "font: bold on, height 280; align: wrap on,horiz center, vert center; borders: bottom medium"
        )
        header_style = xlwt.easyxf(
            "font: bold on; align: horiz center, vert center; borders: bottom medium"
        )
        subheader_style = xlwt.easyxf("font: bold on; align: horiz left")
        data_style = xlwt.easyxf(
            "align: wrap on, horiz center, vert center; borders: left thin, right thin, top thin, bottom thin"
        )
        
        # Set column widths
        ws.col(0).width = 7500  # "ITEM" column (wider for better readability)
        ws.col(1).width = 4000  # "QUANTITY" column
        ws.col(2).width = 6000  # "PRICE PER UNIT (BDT)" column
        ws.col(3).width = 6000  # "TOTAL PRICE (BDT)" column

        # Write sheet title
        ws.write_merge(0, 0, 0, 3, title, title_style)

        # Adjust row height based on number of lines (approximation)
        num_lines = (len(title) // 30) + 1  # Adjust the divisor based on column width
        ws.row(0).height_mismatch = True
        ws.row(0).height = 256 * num_lines  # Each line is roughly 256 units high

        # Section: Revenue Breakdown
        ws.write(2, 0, "Cost Breakdown", subheader_style)
        ws.write(3, 0, "ITEM", header_style)
        ws.write(3, 1, "QUANTITY", header_style)
        ws.write(3, 2, "PRICE PER UNIT (BDT)", header_style)
        ws.write(3, 3, "TOTAL PRICE (BDT)", header_style)

        row = 4
        for data in cost_data.values():
            ws.write(row, 0, data[0], data_style)
            ws.write(row, 1, data[1], data_style)
            ws.write(row, 2, data[2], data_style)
            ws.write(row, 3, data[3], data_style)
            row += 1
        
        ws.write(row, 2, "Total Cost:", subheader_style)
        ws.write(row, 3, total_cost, data_style)

        # Section: Cost Breakdown
        row += 2
        ws.write(row, 0, "Revenue Breakdown", subheader_style)
        row += 1
        ws.write(row, 0, "Revenue Type", header_style)
        ws.write(row, 1, "QUANTITY", header_style)
        ws.write(row, 2, "Revenue / Unit (BDT)", header_style)
        ws.write(row, 3, "Revenue Generated (BDT)", header_style)

        row += 1
        for data in revenue_data.values():
            ws.write(row, 0, data[0], data_style)
            ws.write(row, 1, data[1], data_style)
            ws.write(row, 2, data[2], data_style)
            ws.write(row, 3, data[3], data_style)
            row += 1
        
        ws.write(row, 2, "Total Revenue:", subheader_style)
        ws.write(row, 3, total_revenue, data_style)

        # Approval Section
        row += 3
        ws.write(row, 0, "Approved by:", subheader_style)
        # ws.write(row + 1, 0, budget_data.get("approval", ""), data_style)
        
        # Save the file to a buffer instead of disk
        buffer = BytesIO()
        wb.save(buffer)
        buffer.seek(0)  # Move the cursor to the beginning of the buffer

        return buffer
    
    def get_sc_ag_logo_name(primary):
        if primary == 1:
            return 'IEEE NSU SB Logo'
        elif primary == 2:
            return 'IEEE NSU PES SBC Logo'
        elif primary == 3:
            return 'IEEE NSU RAS SBC Logo'
        elif primary == 4:
            return 'IEEE NSU IAS SBC Logo'
        elif primary == 5:
            return 'IEEE NSU SB WIE AG Logo'
        
    def get_sc_ag_header_color(primary):
        if primary == 1:
            return '#137AAC'
        elif primary == 2:
            return '#659941'
        elif primary == 3:
            return '#602569'
        elif primary == 4:
            return '#008bC2'
        elif primary == 5:
            return '#006699'