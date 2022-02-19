def file_get_bytes(file_path, offset, size):
    try:
        ret = None
        with open(file_path, 'rb') as f:
            f.seek(offset)
            ret = f.read(size)
    except Exception as e:
        print("Exception: {}".format(e))
        return None

    return ret

# -----------------------------------------------------
# some cross file functions, like cross references
# and searches that require scanning the entire file.
# these functions needs to be implemented in a way that
# is scalable and optimized to large files.
# -----------------------------------------------------
# file_get_bytes retreiving n bytes at a time.
def _file_get_bytes( file_path, 
                    start_address=0, 
                    end_address=-1, 
                    at_a_time=8, 
                    buffering=1024):

    if buffering % at_a_time != 0: 
        return None

    try:
        f = open(file_path, 'rb')

        # starting at the start address
        f.seek(start_address)

        while True:
            prev_position = f.tell()

            data = f.read(buffering)

            # reached the end.
            if not data: break
            
            curr_position = f.tell()

            if end_address != -1:
                if curr_position > end_address:
                    curr_position = end_address

            num_of_bytes_to_send = curr_position - prev_position

            data = data[:num_of_bytes_to_send]
            
            if len(data) % at_a_time != 0:
                num_of_iterations = int((len(data) / at_a_time)) + 1
            else:
                num_of_iterations = int((len(data) / at_a_time))

            # do somthing
            for i in range(num_of_iterations):
                if ((i*at_a_time) + at_a_time) > len(data):
                    yield data[(i*at_a_time):len(data)]
                else:
                    yield data[(i*at_a_time):(i*at_a_time)+at_a_time]

            if end_address != -1:
                if curr_position >= end_address:
                    break

    except Exception as e:
        print("Exception: {}".format(e))
