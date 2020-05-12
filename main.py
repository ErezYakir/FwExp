from firewall import fortigatefirewall, checkpointfirewall
from analyzer.analyzer import analyzer
import tkinter as tk
import tkinter.ttk as ttk
import os
from tkinter import filedialog, Tk
from tkinter import font
import pprint
from gui.gui import JSONTreeFrame


try:
    f = checkpointfirewall.CheckpointFirewall("13.90.245.118", "admin", "Aa123456123456", "mongodb://localhost:27017/", "Checkpoint", port=2222)
    f.fetch(fetch_remotely=False)
    f.parseToDb()

    #f2 = fortigatefirewall.FortigateFirewall("52.161.105.178", "yakir", "Aa123456123456", "mongodb://localhost:27017/",
    #                                          "Fortigate")
    #f2.fetch()
    #f2.parseToDb()


    m_analyzer = analyzer("mongodb://localhost:27017/", "Checkpoint")
    root: Tk = tk.Tk()
    root.title('PyJSONViewer')
    root.geometry("800x800")
    menubar = tk.Menu(root)

    app = JSONTreeFrame(root, m_analyzer)

    tool_menu = tk.Menu(menubar, tearoff=0)
    tool_menu.add_command(label="Expand all",
                          accelerator='Ctrl+E', command=app.expand_all)
    tool_menu.add_command(label="Collapse all",
                          accelerator='Ctrl+L', command=app.collapse_all)
    menubar.add_cascade(label="Tools", menu=tool_menu)

    help_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Help", menu=help_menu)

    app.grid(column=0, row=0, sticky=(tk.N, tk.S, tk.E, tk.W))
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)

    app.init_search_box()
    app.init_query_box()

    root.config(menu=menubar)
    root.mainloop()

except  Exception as e:
    print(e)