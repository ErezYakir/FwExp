from firewall import fortigatefirewall, checkpointfirewall
from analyzer.analyzer import analyzer
from firewall.networkobject import NetworkObject
import PySimpleGUI as sg
import pprint

try:
    f = checkpointfirewall.CheckpointFirewall("52.161.93.194", "yakir", "Aa123456123456", "mongodb://localhost:27017/", "Checkpoint")
    f.fetch()
    f.parseToDb()


    m_analyzer = analyzer("mongodb://localhost:27017/", "Checkpoint")
    sg.theme('DarkAmber')  # Add a touch of color
    layout = [[sg.Text('Output window:')],
              [sg.Output(size=(150, 50), key='-OUTPUT-')],
              [sg.In(key='-IN-'), sg.Drop(key='option', values=('Search By Name', 'Search By Id',
                                                                'Get Rules By Source', 'Get Rules By Destination'))],
              [sg.Button('Go'), sg.Button('Clear'), sg.Button('Exit')]]

    window = sg.Window('Firewall Analyzer', layout)
    # Event Loop to process "events" and get the "values" of the inputs
    while True:
        event, values = window.read()
        search = values['-IN-']
        option = values['option']
        if option == 'Search By Name':
            obj = m_analyzer._get_obj_by_name(search)
        if option == 'Get Rules By Source':
            obj = m_analyzer._find_rules_containing_address_in_source(search)
        if option == 'Search By Id':
            obj = m_analyzer._get_obj_by_id(search)
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(obj)
        #print(obj)
        if event in (None, 'Exit'):
            break
        if event == 'Clear':
            window['-OUTPUT-'].update('')

    window.close()

except  Exception as e:
    print(e)