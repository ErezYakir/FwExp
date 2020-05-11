import argparse
import json
import os
import tkinter as tk
import tkinter.ttk as ttk
import webbrowser
from tkinter import filedialog, Tk
from tkinter import font
from tkinter import messagebox
from urllib.parse import urlparse

# === Config ===
MAX_N_SHOW_ITEM = 300
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))


class JSONTreeFrame(ttk.Frame):
    class Listbox(tk.Listbox):
        """
            auto width list box container
        """

        def autowidth(self, maxwidth):
            f = font.Font(font=self.cget("font"))
            pixels = 0
            for item in self.get(0, "end"):
                pixels = max(pixels, f.measure(item))
            # bump listbox size until all entries fit
            pixels = pixels + 10
            width = int(self.cget("width"))
            for w in range(0, maxwidth + 1, 5):
                if self.winfo_reqwidth() >= pixels:
                    break
                self.config(width=width + w)

    def __init__(self, master, analyzer):
        super().__init__(master)
        self.master = master
        self.tree = ttk.Treeview(self)
        self.create_widgets()
        self.sub_win = None
        self.search_box = None
        self.bottom_frame = None
        self.search_box = None
        self.search_label = None
        self.set_table_data_from_json({})
        self.m_analyzer = analyzer

    def create_widgets(self):
        self.tree.bind('<Double-1>', self.click_item)

        ysb = ttk.Scrollbar(
            self, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=ysb.set)

        self.tree.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        ysb.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

    def init_search_box(self):
        self.bottom_frame = tk.Frame(self)
        self.bottom_frame.grid(column=0, row=3, sticky=(tk.N, tk.S, tk.E, tk.W))

        self.find_label = tk.Label(self.bottom_frame, text="Find:")
        self.find_label.pack(side=tk.LEFT)

        self.search_box = tk.Entry(self.bottom_frame)
        self.search_box.pack(fill='x')
        self.search_box.bind('<Key>', self.find_word)

    def init_query_box(self):
        self.query_frame = tk.Frame(self)
        self.query_frame.grid(column=0, row=2, sticky=(tk.N, tk.S, tk.E, tk.W))

        self.query_btn = tk.Button(self.query_frame, text="Go!", command=self.search_query_action)
        self.query_btn.pack(side=tk.RIGHT)
        self.tkvar = tk.StringVar(self.master)
        # Dictionary with options
        choices = {'Search By Name', 'Search By Id', 'Get Rules for Source', 'Get Rules for Destination'}
        self.tkvar.set('Search By Name')  # set the default option
        self.popupMenu = tk.OptionMenu(self.query_frame, self.tkvar, *choices)
        self.popupMenu.pack(side=tk.RIGHT)
        self.query_box = tk.Entry(self.query_frame)
        self.query_box.pack(fill='x')

    def search_query_action(self):
        choice = self.tkvar.get()
        query = self.query_box.get()
        if choice == 'Search By Name':
            result = self.m_analyzer._get_obj_by_name(query)
        elif choice == 'Search By Id':
            result = self.m_analyzer._get_obj_by_id(query)
        elif choice == 'Get Rules for Source':
            result = self.m_analyzer._find_rules_containing_address_in_source(query)
        self.set_table_data_from_json(result)

    def insert_node(self, parent, key, value):
        node = self.tree.insert(parent, 'end', text=key, open=False)

        if value is None:
            return

        if type(value) is not dict:
            if type(value) is list:
                value = value[0:MAX_N_SHOW_ITEM]
            self.tree.insert(node, 'end', text=value, open=False)
        else:
            for (key, value) in value.items():
                self.insert_node(node, key, value)

    def click_item(self, _):
        """
        Callback function when an item is clicked

        :param _: event arg (not used)
        """
        item_id = self.tree.selection()
        item_text = self.tree.item(item_id, 'text')

        if self.is_url(item_text):
            webbrowser.open(item_text)

    def expand_all(self):
        for item in self.get_all_children(self.tree):
            self.tree.item(item, open=True)

    def collapse_all(self):
        for item in self.get_all_children(self.tree):
            self.tree.item(item, open=False)

    def find_window(self):
        self.search_box = tk.Entry(self.master)
        self.search_box.pack()
        self.search_box.bind('<Key>', self.find_word)

    def find_word(self, _):
        search_text = self.search_box.get()
        self.find(search_text)

    def find(self, search_text):
        if not search_text:
            return
        self.collapse_all()
        for item_id in self.get_all_children(self.tree):
            item_text = str(self.tree.item(item_id, 'text'))
            if search_text.lower() in item_text.lower():
                self.tree.see(item_id)

    def get_all_children(self, tree, item=""):
        children = tree.get_children(item)
        for child in children:
            children += self.get_all_children(tree, child)
        return children

    def select_listbox_item(self, evt):
        w = evt.widget
        index = int(w.curselection()[0])
        value = w.get(index)
        self.set_table_data_from_json(value)
        self.sub_win.destroy()  # close window

    def set_table_data_from_json(self, json_data):
        self.delete_all_nodes()
        self.insert_nodes(json_data)

    def delete_all_nodes(self):
        for i in self.tree.get_children():
            self.tree.delete(i)

    def insert_nodes(self, data):
        if type(data) == list:
            for single_data in data:
                parent = ""
                for (key, value) in single_data.items():
                    self.insert_node(parent, key, value)
                self.tree.insert(parent, 'end', text="-"*500, open=False)
        else:
            parent = ""
            for (key, value) in data.items():
                self.insert_node(parent, key, value)

    def open_url(self, url):
        if self.is_url(url):
            webbrowser.open(url)
        else:
            print("Error: this is not url:", url)

    @staticmethod
    def is_url(text):
        """check input text is url or not

        :param text: input text
        :return: url or not
        """
        parsed = urlparse(text)
        return all([parsed.scheme, parsed.netloc, parsed.path])

    @staticmethod
    def get_unique_list(seq):
        seen = []
        return [x for x in seq if x not in seen and not seen.append(x)]

    @staticmethod
    def load_json_data(file_path):
        with open(file_path) as f:
            return json.load(f)
