import os
import zipfile
import json
from os import listdir
from os.path import join


def unzip_cves(input_dir="zip", output_dir="json"):
    """Unzip downloaded CVE JSON zip files"""
    # Create output directory for JSON files if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    # Get all zip files from the input directory
    files_to_unzip = [f for f in listdir(input_dir)]
    files_to_unzip.sort()
    print(f"\nUnzipping files...")
    for filename in files_to_unzip:
        zip_filepath = os.path.join(input_dir, filename)
        print(f"Unzipping: {filename}...")
        try:
            with zipfile.ZipFile(zip_filepath, 'r') as archive:
                archive.extractall(output_dir)
                print(f"✓ Extracted {filename}")
        except zipfile.BadZipFile:
            print(f"✗ Failed to unzip {filename}: Not a valid zip file.")
        except Exception as e:
            print(f"✗ Failed to unzip {filename}: {e}")
    print("\nUnzip complete!")


if __name__ == "__main__":
    # 2. Extract json files from zip files
    unzip_cves()