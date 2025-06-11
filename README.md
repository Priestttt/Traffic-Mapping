# Traffic Map Visualization

This project visualizes network traffic on an interactive world map using. It displays real-time traffic routes, geolocation data, and traffic statistics.

![Demo](https://s2.ezgif.com/tmp/ezgif-2ffd09e3a07ab2.gif)

## Warning 

This project is built with sticks for entertainment purposes only and does not include any security fixes.

## Setup and Usage

1. Clone or download the repository.
2. ```bash
   git clone https://github.com/yourusername/traffic-map.git
   cd traffic-map 
   python -m pip install -r requirements.txt
   python3 server.py
4. Go to http://127.0.0.1/ in Browser

## Data Format

- **Traffic data** (`/traffic`): Array of objects with fields:
  - `source`: `{ ip, city, country, latitude, longitude }`
  - `destination`: `{ ip, city, country, latitude, longitude }`
  - `timestamp`: unique identifier
  - `type`: protocol or attack type

## Customization

- Map style can be changed by modifying the tile layer URL in `index.html`.
- Neon colors and styles are defined in CSS for easy adjustment.
