import os
import struct
import tkinter as tk
from tkinter import filedialog, messagebox
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# Funcție pentru verificarea unui fișier SWF
def parse_swf(file_path):
    vulnerabilities = {
        "Use-After-Free": 0,
        "Double-Free": 0,
        "Buffer Overflow": 0,
        "Out-of-Bounds Access": 0,
        "Heap Spraying": 0
    }
    try:
        with open(file_path, "rb") as f:
            header = f.read(3)
            if header not in (b"FWS", b"CWS"):
                return None, "Nu este un fișier SWF valid."
            
            version = struct.unpack("B", f.read(1))[0]
            file_size = struct.unpack("<I", f.read(4))[0]
            
            # Detectare simplă a vulnerabilităților (simulare)
            if version < 10:
                vulnerabilities["Use-After-Free"] += 1  # Simulăm o vulnerabilitate UAF pentru versiuni vechi
            if file_size > 10_000_000:
                vulnerabilities["Heap Spraying"] += 1  # Fișierele mari sunt suspecte pentru heap spraying
            
            # Verificare exemplară a secțiunilor (simulare)
            f.seek(8)  # Sărim peste header
            data = f.read()
            if b"ActionScript" in data:
                vulnerabilities["Buffer Overflow"] += 1
                vulnerabilities["Out-of-Bounds Access"] += 1  # Simulăm prezența codului nesigur

        return vulnerabilities, None
    except Exception as e:
        return None, f"Eroare la procesarea fișierului: {str(e)}"

# Funcție pentru generarea raportului text
def generate_report(file_name, vulnerabilities):
    total_vulnerabilities = sum(vulnerabilities.values())
    severity = "Scăzută"
    if total_vulnerabilities >= 5:
        severity = "Critică"
    elif total_vulnerabilities >= 3:
        severity = "Medie"
    
    report = []
    report.append(f"Raport de Securitate pentru Fișierul {file_name}")
    report.append("-" * 50)
    report.append("Vulnerabilități găsite:")
    for vuln, count in vulnerabilities.items():
        report.append(f"- {vuln}: {count} cazuri")
    report.append("\nStatistică:")
    report.append(f"- Total vulnerabilități: {total_vulnerabilities}")
    report.append(f"- Severitate: {severity}")
    return "\n".join(report)

# Funcție pentru salvarea raportului PDF
def save_pdf_report(file_name, vulnerabilities, output_path):
    report = generate_report(file_name, vulnerabilities)

    c = canvas.Canvas(output_path, pagesize=letter)
    c.setFont("Helvetica", 12)
    y = 750

    for line in report.split("\n"):
        if y < 50:  # Dacă depășim pagina, adăugăm o nouă pagină
            c.showPage()
            c.setFont("Helvetica", 12)
            y = 750
        c.drawString(30, y, line)
        y -= 15

    c.save()
    messagebox.showinfo("Raport PDF", f"Raportul a fost salvat în {output_path}")

# Funcție pentru analiza unui fișier și salvarea raportului PDF
def analyze_single_file():
    file_path = filedialog.askopenfilename(filetypes=[("SWF Files", "*.swf")])
    if not file_path:
        return

    vulnerabilities, error = parse_swf(file_path)
    if error:
        result_text.insert(tk.END, f"Eroare: {error}\n")
        return

    report = generate_report(os.path.basename(file_path), vulnerabilities)
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, report + "\n")

    # Salvare PDF
    output_path = file_path.replace(".swf", "_raport.pdf")
    save_pdf_report(os.path.basename(file_path), vulnerabilities, output_path)

# Funcție pentru scanarea și generarea raportului pentru un folder
def analyze_folder_and_generate_report():
    folder_path = filedialog.askdirectory()
    if not folder_path:
        return

    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, f"Scanare folder: {folder_path}\n")
    result_text.insert(tk.END, "-" * 50 + "\n")

    report_lines = []
    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".swf"):
                file_path = os.path.join(root, file)
                vulnerabilities, error = parse_swf(file_path)
                if error:
                    report_lines.append(f"{file}: Eroare - {error}")
                else:
                    report_lines.append(generate_report(file, vulnerabilities))

    # Afișare raport în interfață
    result_text.insert(tk.END, "\n".join(report_lines) + "\n")

    # Salvare raport PDF pentru folder
    output_path = os.path.join(folder_path, "raport_scanare_folder.pdf")
    save_pdf_report("Folder Scanare", {}, output_path)

# Interfața principală
root = tk.Tk()
root.title("Scanner Vulnerabilități SWF")
root.geometry("700x500")

# Butoane pentru analiză și generare rapoarte
analyze_single_button = tk.Button(root, text="Analizează fișier SWF", command=analyze_single_file, width=25)
analyze_single_button.pack(pady=10)

analyze_folder_button = tk.Button(root, text="Scanare folder și salvare raport PDF", command=analyze_folder_and_generate_report, width=25)
analyze_folder_button.pack(pady=10)

result_text = tk.Text(root, height=20, width=80)
result_text.pack(pady=10)

# Rulează aplicația
root.mainloop()
