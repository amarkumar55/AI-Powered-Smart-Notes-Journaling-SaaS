from media.countries import  country
from media.states import states_lookup
from media.cities import cities_by_state

def get_all_countries():
    return country

def get_states_by_country(country_code):
    return states_lookup.get(country_code, [])

def get_cities_by_state(state_code):
    return cities_by_state.get(state_code, [])

def get_all_timezone():
    return [
        cty_data['timezones'][0]['zoneName']
        for cty_data in country.values()
        if cty_data.get('timezones')
    ]
def get_all_code():
    return [ cty_data['phonecode'] for cty_data in country.values()]