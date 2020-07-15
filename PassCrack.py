import multiprocessing as mp
from hashlib import sha256
from os import path


def word_rules(words, user_hash, found, hash_match, pipe_lock, send_lock):
    for word in words:
        word = word.rstrip()  # Remove newline character

        # Rule 5
        comp_hash = sha256()  # Hash to compare with 'userHash'
        binary_word = bytes(word.encode())  # Convert modified word to binary for hash func.
        comp_hash.update(binary_word)

        # Check to see if hash of modified word matches user's
        if comp_hash.hexdigest() == user_hash:
            print("Password found in rule")
            pipe_lock.acquire()
            found.value = 1
            hash_match.send(word)
            send_lock.acquire()
            pipe_lock.release()
            break  # Break from outer for-loop

        # Rule 3
        guess = ""
        for ch in word:
            tempCh = ch
            if (ch == 'a'):
                tempCh = '@'
            elif (ch == 'l'):
                tempCh = '1'
            guess += tempCh

        comp_hash = sha256()  # Hash to compare with 'userHash'
        binary_word = bytes(guess.encode())  # Convert modified word to binary for hash func.
        comp_hash.update(binary_word)

        # Check to see if hash of modified word matches user's
        if comp_hash.hexdigest() == user_hash:
            print("Password found in rule")
            pipe_lock.acquire()
            found.value = 1
            hash_match.send(guess)
            send_lock.acquire()
            pipe_lock.release()
            break  # Break from outer for-loop

        if len(word) == 7:
            # Format word for hash function
            word = word.capitalize()

            combination = [word, '?']  # List to join word and appended number
            for apd in range(10):
                comp_hash = sha256()  # Hash to compare with 'userHash'
                combination[1] = str(apd)  # Append 'i' to 'word'
                binary_word = bytes(''.join(combination).encode())  # Convert modified word to binary for hash func.
                comp_hash.update(binary_word)

                # Check to see if hash of modified word matches user's
                if comp_hash.hexdigest() == user_hash:
                    print("Password found in rule")
                    pipe_lock.acquire()
                    found.value = 1
                    hash_match.send(''.join(combination))
                    send_lock.acquire()
                    pipe_lock.release()
                    break  # Break from inner for-loop, allowing process to terminate in the section directly below.
            pipe_lock.acquire()
            if found.value == 1:
                pipe_lock.release()
                break  # Break from outer for-loop
            else:
                pipe_lock.release()

    # Checks to see if either all combinations were parsed or a match was found in any process
    pipe_lock.acquire()
    print("Has a match been found?")
    if found.value == 1:
        print("Match has been found!")
        pipe_lock.release()
    elif found.value > mp.cpu_count() * -1 + 3:
        print("No match, but other processes still able to find a match...")
        found.value -= 1
        pipe_lock.release()
    else:
        print("No processes were able to find a match.")
        found.value -= 1
        hash_match.send('')
        send_lock.acquire()
        pipe_lock.release()


def rule_2(user_hash, found, hash_match, pipe_lock, send_lock):
    # Rule 2
    specialCharList = ['*', '~', '!', '#']

    # Generate guesses
    i = 0
    while (i < 10000):

        # Generate number string
        if (i < 10):
            numString = "000" + str(i)
        elif (i < 100):
            numString = "00" + str(i)
        elif (i < 1000):
            numString = "0" + str(i)
        else:
            numString = str(i)

        # Generate guesses by prepending special chars
        j = 0
        while (j < 4):
            guess = specialCharList[j] + numString
            # Check if guess hash matches actual hash
            comp_hash = sha256(guess.encode()).hexdigest()

            if comp_hash == user_hash:
                print("Password found in rule")
                pipe_lock.acquire()
                found.value = 1
                hash_match.send(guess)
                send_lock.acquire()
                pipe_lock.release()
                return  # Kill process, as a match has been found.

            j += 1

        # Check to see if any other process found a match
        pipe_lock.acquire()
        if found.value == 1:
            pipe_lock.release()
            return  # Kill process, as a match has been found.
        else:
            pipe_lock.release()

        i += 1

    # Checks to see if either all combinations were parsed or a match was found in any process
    pipe_lock.acquire()
    print("Has a match been found?")
    if found.value == 1:
        print("Match has been found!")
        pipe_lock.release()
    elif found.value > mp.cpu_count() * -1 + 1:
        print("No match, but other processes still able to find a match...")
        found.value -= 1
        pipe_lock.release()
    else:
        print("No processes were able to find a match.")
        found.value -= 1
        hash_match.send('')
        send_lock.acquire()
        pipe_lock.release()


def rule_4(user_hash, found, hash_match, pipe_lock, send_lock):
    # Generate guesses for 1 digit string
    for i in range(10):
        guess = str(i)

        # Check if guess hash matches actual hash
        comp_hash = sha256(guess.encode()).hexdigest()

        if comp_hash == user_hash:
            print("Password found in rule")
            pipe_lock.acquire()
            found.value = 1
            hash_match.send(guess)
            send_lock.acquire()
            pipe_lock.release()
            return  # Kill process, as a match has been found.

    # Check to see if any other process found a match
    pipe_lock.acquire()
    if found.value == 1:
        pipe_lock.release()
        return  # Kill process, as a match has been found.
    else:
        pipe_lock.release()

    # Generate guesses for 2 digit string
    for i in range(100):
        if (i < 10):
            guess = "0" + str(i)
        else:
            guess = str(i)

        # Check if guess hash matches actual hash
        comp_hash = sha256(guess.encode()).hexdigest()

        if comp_hash == user_hash:
            print("Password found in rule")
            pipe_lock.acquire()
            found.value = 1
            hash_match.send(guess)
            send_lock.acquire()
            pipe_lock.release()
            return  # Kill process, as a match has been found.

    # Check to see if any other process found a match
    pipe_lock.acquire()
    if found.value == 1:
        pipe_lock.release()
        return  # Kill process, as a match has been found.
    else:
        pipe_lock.release()

    # Generate guesses for 3 digit string
    for i in range(1000):
        if (i < 10):
            guess = "00" + str(i)
        elif (i < 100):
            guess = "0" + str(i)
        else:
            guess = str(i)

        # Check if guess hash matches actual hash
        comp_hash = sha256(guess.encode()).hexdigest()

        if comp_hash == user_hash:
            print("Password found in rule")
            pipe_lock.acquire()
            found.value = 1
            hash_match.send(guess)
            send_lock.acquire()
            pipe_lock.release()
            return  # Kill process, as a match has been found.

    # Check to see if any other process found a match
    pipe_lock.acquire()
    if found.value == 1:
        pipe_lock.release()
        return  # Kill process, as a match has been found.
    else:
        pipe_lock.release()

    # Generate guesses for 4 digit string
    for i in range(10000):
        if (i < 10):
            guess = "000" + str(i)
        elif (i < 100):
            guess = "00" + str(i)
        elif (i < 1000):
            guess = "0" + str(i)
        else:
            guess = str(i)

        # Check if guess hash matches actual hash
        comp_hash = sha256(guess.encode()).hexdigest()

        if comp_hash == user_hash:
            print("Password found in rule")
            pipe_lock.acquire()
            found.value = 1
            hash_match.send(guess)
            send_lock.acquire()
            pipe_lock.release()
            return  # Kill process, as a match has been found.

    # Check to see if any other process found a match
    pipe_lock.acquire()
    if found.value == 1:
        pipe_lock.release()
        return  # Kill process, as a match has been found.
    else:
        pipe_lock.release()

    # 5 dig string
    for i in range(100000):
        if (i < 10):
            guess = "0000" + str(i)
        elif (i < 100):
            guess = "000" + str(i)
        elif (i < 1000):
            guess = "00" + str(i)
        elif (i < 10000):
            guess = "0" + str(i)
        else:
            guess = str(i)

        comp_hash = sha256(guess.encode()).hexdigest()

        if comp_hash == user_hash:
            print("Password found in rule")
            pipe_lock.acquire()
            found.value = 1
            hash_match.send(guess)
            send_lock.acquire()
            pipe_lock.release()
            return  # Kill process, as a match has been found.

    # Check to see if any other process found a match
    pipe_lock.acquire()
    if found.value == 1:
        pipe_lock.release()
        return  # Kill process, as a match has been found.
    else:
        pipe_lock.release()

    # 6 dig string
    for i in range(1000000):
        if (i < 10):
            guess = "00000" + str(i)
        elif (i < 100):
            guess = "0000" + str(i)
        elif (i < 1000):
            guess = "000" + str(i)
        elif (i < 10000):
            guess = "00" + str(i)
        elif (i < 100000):
            guess = "0" + str(i)
        else:
            guess = str(i)

        # Check if guess hash matches actual hash
        comp_hash = sha256(guess.encode()).hexdigest()

        if comp_hash == user_hash:
            print("Password found in rule")
            pipe_lock.acquire()
            found.value = 1
            hash_match.send(guess)
            send_lock.acquire()
            pipe_lock.release()
            return  # Kill process, as a match has been found.

    # Check to see if any other process found a match
    pipe_lock.acquire()
    if found.value == 1:
        pipe_lock.release()
        return  # Kill process, as a match has been found.
    else:
        pipe_lock.release()

    # 7 dig string
    for i in range(10000000):
        if (i < 10):
            guess = "000000" + str(i)
        elif (i < 100):
            guess = "00000" + str(i)
        elif (i < 1000):
            guess = "0000" + str(i)
        elif (i < 10000):
            guess = "000" + str(i)
        elif (i < 100000):
            guess = "00" + str(i)
        elif (i < 1000000):
            guess = "0" + str(i)
        else:
            guess = str(i)

        # Check if guess hash matches actual hash
        comp_hash = sha256(guess.encode()).hexdigest()

        if comp_hash == user_hash:
            print("Password found in rule")
            pipe_lock.acquire()
            found.value = 1
            hash_match.send(guess)
            send_lock.acquire()
            pipe_lock.release()
            return  # Kill process, as a match has been found.

    # Checks to see if either all combinations were parsed or a match was found in any process
    pipe_lock.acquire()
    print("Has a match been found?")
    if found.value == 1:
        print("Match has been found!")
        pipe_lock.release()
    elif found.value > mp.cpu_count() * -1 + 1:
        print("No match, but other processes still able to find a match...")
        found.value -= 1
        pipe_lock.release()
    else:
        print("No processes were able to find a match.")
        found.value -= 1
        hash_match.send('')
        send_lock.acquire()
        pipe_lock.release()


def crack_passwords(hash_file):
    out = open('CrackedPasswords.txt', 'w')  # out file for cracked passwords

    # Open word list file and put each line (or word) as an element in word_list
    word_list = open(path.join('WordLists', 'WindowsWords.txt'), 'r').readlines()

    with open(hash_file, 'r') as file:

        for line in file:
            # multiprocessing.Value to keep track of which thread has found a match for the hash being compared to results
            # from rules 1-5 specified in the assignment instructions. This value is shared between threads.
            # 'found' can have three sets of possible values:
            # 1. 0, when no match has yet been found but rules are still running to find one.
            # 2. 1, when a match has been found.
            # 3. >-1, when no match was found with any of the rules.
            found = mp.Value('i')
            found.value = 0

            # multiprocessing.Pipe to return to the parent the password found in a rule method
            # which matches the user's hash, if any such password was found.
            hash_match_recv, hash_match_send = mp.Pipe()

            # Locks used to make sure that no rule method tries to send a match to the parent before it is ready to
            # receive the data
            pipe_lock = mp.Lock()
            send_lock = mp.Lock()
            pipe_lock.acquire()
            send_lock.acquire()

            # Linux GECOS fields
            if (line.find(':') != -1):
                # Separate the username from their encrypted password
                user_and_hash = line.split(':')
                user = user_and_hash[0]
                passwd_hash = user_and_hash[1].rstrip()
                out.write(user + ':')
            # Raw hashes
            else:
                passwd_hash = line

            # Use multiprocessing if the host processor has the capability to run 4 or more threads
            if mp.cpu_count() >= 4:

                # Divides word list into chunks which will be processed in parallel
                process_list = []
                thread_count = 0
                word_count = len(word_list)
                chunk_size = word_count // (mp.cpu_count() - 2)
                leftover = word_count % (mp.cpu_count() - 2)  # Leftover words after div. evenly among threads
                chunks = []
                for t in range(mp.cpu_count() - 2):
                    chunks.append(word_list[t * chunk_size: (t + 1) * chunk_size])
                for l in range(leftover):
                    chunks[mp.cpu_count() - 3].append(word_list[len(word_list) - l - 1])

                # Spawning processes
                while thread_count < mp.cpu_count():
                    if thread_count < mp.cpu_count() - 2:
                        if thread_count == mp.cpu_count() - 3:
                            process_list.append(mp.Process(
                                target=word_rules,
                                args=(chunks[thread_count],
                                      passwd_hash, found, hash_match_send, pipe_lock, send_lock)))
                        else:
                            process_list.append(mp.Process(target=word_rules,
                                                           args=(chunks[thread_count],
                                                                 passwd_hash, found, hash_match_send, pipe_lock,
                                                                 send_lock)))

                        process_list[thread_count].start()
                        thread_count += 1

                    else:
                        # Rule 2 process
                        process_list.append(mp.Process(
                            target=rule_2,
                            args=(passwd_hash, found, hash_match_send, pipe_lock, send_lock)))
                        process_list[thread_count].start()

                        # Rule 4 process
                        process_list.append(mp.Process(
                            target=rule_4,
                            args=(passwd_hash, found, hash_match_send, pipe_lock, send_lock)))
                        process_list[thread_count + 1].start()

                        thread_count += 2

                try:
                    while found.value > -1 * mp.cpu_count() and found.value != 1:
                        pipe_lock.release()
                        print('Waiting to receive message...')
                        hash_match = hash_match_recv.recv()
                        print('Received message')
                        send_lock.release()
                        pipe_lock.acquire()
                        print('Acquired pipelock in main')
                except EOFError:  # Unable to find a match for the examined hash
                    hash_match = ''
                # Wait for all processes to finish before continuing
                print('Waiting for processes to finish...')
                pipe_lock.release()
                for p in process_list:
                    p.join()

                if hash_match is not '':
                    print('Writing password to out...')
                    out.write(user + ':' + passwd_hash + ':' + hash_match + "\n")
                else:
                    out.write('\n')

        file.close()
        out.close()


if __name__ == '__main__':
    crack_passwords('PasswordHashes.txt')
