import string
import random
import math
import time
from cryptography.fernet import Fernet
import matplotlib.pyplot as plt
from Crypto.Hash import HMAC, SHA256

DUMMY_LEN = 3
DUM_VAL = 48
DATA_LEN = 4
DEFAULT_DATA = 'aaaa'
INTERVAL = 10
BUCKET_SIZE = 4  # Suffices as said in page 5 of the article, and explaned in Section 7.1.
KEY_LEN = 10


class Node:
    """
    Class represents a node in the tree.
    """

    def __init__(self, parent=None):
        self.parent = parent
        self.left = self.right = self.value = None


class PerfectTree:
    """
    Class for perfect binary tree.
    """
    def __init__(self, size):
        self.size = self.fix_size(size+1)
        self.height = int(math.log(self.size, 2))
        self.tree_arr = [[Node()]]
        self.root = self.tree_arr[0][0]
        self.build_tree_arr()
        self.leaves = self.tree_arr[-1]

    def build_tree_arr(self):
        """
        Responsible for building the tree as an array.
        """
        for level in range(self.height):
            self.tree_arr.append([])
            for cur_node in self.tree_arr[level]:
                new_left, new_right = Node(cur_node), Node(cur_node)
                cur_node.left, cur_node.right = new_left, new_right
                self.tree_arr[level+1].extend([new_left, new_right])

    @staticmethod
    def fix_size(size):
        """
        :param size: Int size of the tree
        :return: Int of the fitted size for the binary tree to be perfect.
        """
        if math.ceil(math.log(size, 2)) != math.floor(math.log(size, 2)):
            size += 1
        return size-1


class Server:
    """
    The server class. Stores the (full binary) tree structure.
    The server is oblivious to data content and the client's access patterns.
    Unable to trick the client into accepting corrupt or outdated data (data integrity).
    """
    def __init__(self, data_blocks):
        """
        Initializes new server with a new binary tree.
        :param data_blocks: Int number of data_blocks supported by the server.
        """
        self.data_blocks = data_blocks
        self.bucket_size = BUCKET_SIZE
        self._tree = PerfectTree(data_blocks)
        self.height = self._tree.height
        self.leaves_num = len(self._tree.leaves)
        self.leaf_min = 2 ** (self.height+1)
        self.leaf_max = self.leaf_min * 2 - 1

    # === GET Methods ===

    def get_root(self):
        """
        Returns the root of the server's tree.
        """
        return self._tree.root

    def get_leaf(self, i):
        """
        Get the i'th leaf.
        :param i: int in size num of leaves.
        :return: Node object which positioned at the i'th leaves index.
        """
        return self._tree.leaves[i]

    def get_node_in_level(self, i, j):
        """
        Get the node in position i on the j'th level.
        :param i: int of tree's level.
        :param j: int node in te i'th level.
        :return: Node object of the j'th node in the i'th level of the tree.
        """
        return self._tree.tree_arr[i][j]

    def num_nodes_in_level(self, i):
        """
        Get number of nodes in the i'th level.
        :param i: int level to check.
        :return: int number of nodes in the i'th level
        """
        return len(self._tree.tree_arr[i])


class Client:
    """
    Class represent a client.
    """
    def __init__(self):
        """
        Initialize the memory and encryption key of the client.
        All fields should be super private.
        """
        self.__memory = dict()
        self.__key = Fernet.generate_key()
        self.__fernet = Fernet(self.__key)  # Enc

    def store_data(self, server, id, data):
        """
        Used for the client to store data associated with an ID on the server.
        :param server: The server object to store the data.
        :param id: Int for the ID of the data (Unique).
        :param data: String with 4 chars represents the data to be stored.
        """
        if id in self.__memory:
            return 'ID already exists. Please delete it first'
        tree_root = server.get_root()
        if tree_root.value is None:  # Hasn't initialized you
            self._fill_server_with_dummies(server)
        hmac = HMAC.new(self.__key, digestmod=SHA256)
        hmac.update(str(id).encode() + data.encode())
        self.__memory[id] = [bin(random.randint(server.leaf_min, server.leaf_max))[2:],
                             hmac.hexdigest()]
        for key in tree_root.value:  # Insert data to the root
            if self.__fernet.decrypt(
                    tree_root.value[key])[0] == DUM_VAL:  # Dummy
                del tree_root.value[key]
                tree_root.value[self.__fernet.encrypt(str(id).encode())] =\
                    self.__fernet.encrypt(('1'+data).encode())
                self._encrypt_node(tree_root)
                break
        self._push_down(server)

    def retrieve_data(self, server, id, data=None):
        """
        Used for the client to retrieve data given a name.
        :param server: The server object to retrieve the data from.
        :param id: Int for the ID of the data to retrieve (Unique).
        :return: The data retrieved from the server.
                 Should return None if the data does not exist.
        """
        data = None
        path = self.__memory[id][0][1:]
        cur_node = server.get_root()
        for level in range(len(path)):
            for key in cur_node.value:
                if self.__fernet.decrypt(key).decode() == str(id):
                    data = self.__fernet.decrypt(cur_node.value[key]).decode()[1:]
                    del cur_node.value[key]  # Remove data from current bucket
                    cur_node.value[self.__fernet.encrypt(
                        Client.get_random_string(DUMMY_LEN).encode())] =\
                        self.__fernet.encrypt(b'00000')  # Add dummy
                    del self.__memory[id]
                    self.store_data(server, id, data)
                    break
            if data is not None:
                break
            cur_node = cur_node.left if path[level] == 0 else cur_node.right
        if data is None:  # data does not exist
            return None
        # 2 Steps Verification (Verification)
        if len(data) != DATA_LEN or type(data) != str:
            return 'Invalid data was returned by the server'
        hmac = HMAC.new(self.__key, digestmod=SHA256)
        hmac.update(str(id).encode() + data.encode())
        try:
            hmac.hexverify(self.__memory[id][1])
        except ValueError:
            return 'The given id data was corrupted'
        return data

    def delete_data(self, server, id, data=None):
        """
        Used for the client to delete data associated with an ID from the server.
        :param server: The server object to delete the data from.
        :param id: Int for the ID of the data to delete (Unique).
        :return: Data that has removed, None if the data does not exist.
        """
        data = None
        path = self.__memory[id][0][1:]
        cur_node = server.get_root()
        for level in range(len(path)):
            for key in cur_node.value:
                if self.__fernet.decrypt(key).decode() == str(id):
                    data = self.__fernet.decrypt(cur_node.value[key])[1:]
                    del cur_node.value[key]
                    cur_node.value[self.__fernet.encrypt(
                        Client.get_random_string(DUMMY_LEN).encode())] =\
                        self.__fernet.encrypt(b'00000')  # Add dummy
                    break
            if data is not None:
                break
            cur_node = cur_node.left if path[level] == 0 else cur_node.right
        return data

    # ===== PRIVATE METHODS =====

    def _push_down(self, server):
        """
        Used for preventing overflow in the server's tree.
        Chooses two buckets in each layer at random, chooses file at random
        from each bucket and writes it to the correct child.
        """
        for level in range(server.height + 1):
            if level == server.height:
                return
            if level == 0:  # Root - pick only one node
                self._rand_and_push(server.get_root(), server, level)
            else:  # level > 0
                rand1 = random.randint(0, server.num_nodes_in_level(level)-1)
                rand2 = random.randint(0, server.num_nodes_in_level(level)-1)
                while rand1 == rand2:  # Force different nodes
                    rand2 = random.randint(0, server.num_nodes_in_level(level)-1)
                node1 = server.get_node_in_level(level, rand1)
                node2 = server.get_node_in_level(level, rand2)
                for s_node in [node1, node2]:
                    self._rand_and_push(s_node, server, level)

    def _rand_and_push(self, node, server, level):
        """
        Randomize 2 different elements in a node and pushes them to the next level.
        :param node: Node object to pick elements from.
        :param server: Server object which contains the node.
        :param level: Current level of pushing.
        """
        rand1 = random.randint(0, server.bucket_size-1)
        key1 = list(node.value.keys())[rand1]
        data1 = node.value[key1]
        rand2 = random.randint(0, server.bucket_size-1)
        while rand1 == rand2:  # Force different key
            rand2 = random.randint(0, server.bucket_size-1)
        key2 = list(node.value.keys())[rand2]
        data2 = node.value[key2]
        self._push_selected_data(key1, data1, node, level)
        self._push_selected_data(key2, data2, node, level)

    def _push_selected_data(self, key, data, prev_node, level):
        """
        Pushes key and data to the next node in the path to their leaf.
        :param key: str value to be pushed.
        :param data: str value to be pushed
        :param prev_node: Node object contains the given data.
        :param level: Current level of pushing.
        """
        dec_key = self.__fernet.decrypt(key).decode()
        dec_data = self.__fernet.decrypt(data)
        if dec_data[0] == DUM_VAL:  # Dummy
            direction = random.randint(0, 1)
        else:
            direction = self.__memory[int(dec_key)][0][level]
        next_node = prev_node.left if direction == 0 else prev_node.right
        # Delete and place dummy instead
        del prev_node.value[key]
        prev_node.value[self.__fernet.encrypt(
            Client.get_random_string(DUMMY_LEN).encode())] =\
            self.__fernet.encrypt(b'00000')
        # Delete dummy from next and push to dict
        for cur_key in next_node.value:
            if self.__fernet.decrypt(next_node.value[cur_key])[0] == DUM_VAL:
                del next_node.value[cur_key]
                next_node.value[key] = data  # Already encrypted
                return

    def _fill_server_with_dummies(self, server):
        """
        Fills all of the server's binary tree buckets with dummy values.
        """
        for level in range(server.height + 1):
            for j in range(server.num_nodes_in_level(level)):
                node = server.get_node_in_level(level, j)
                node.value = dict()
                for i in range(server.bucket_size):
                    node.value[self.__fernet.encrypt(
                        Client.get_random_string(DUMMY_LEN).encode())] =\
                        self.__fernet.encrypt(b'00000')  # Add dummy

    def _encrypt_node(self, node):
        """
        Re-encrypts a given node's value.
        :param node: Node object to re-encrypt
        """
        new_dict = dict()
        for key in node.value:
            dec_key, dec_val =\
                self.__fernet.decrypt(key).decode(),\
                self.__fernet.decrypt(node.value[key]).decode()
            enc_key, enc_val =\
                self.__fernet.encrypt(str(dec_key).encode()),\
                self.__fernet.encrypt(dec_val.encode())
            new_dict[enc_key] = enc_val
        node.value = new_dict

    def _print_node_values(self, node):
        """
        Prints all given node's values after decryption (for testing purposes).
        :param node: Node to be printed.
        """
        for key in node.value:
            dec_key, dec_val =\
                self.__fernet.decrypt(key).decode(),\
                self.__fernet.decrypt(node.value[key]).decode()
            print('Key is {}, Value is {}'.format(dec_key, dec_val))

    # ===== STATIC METHODS ===== #

    @staticmethod
    def get_random_string(length):
        """
        Generates a random string.
        :param length: int length of the string to generate.
        :return: string.
        """
        # Choose from all lowercase letter
        letters = string.ascii_lowercase
        result_str = ''.join(random.choice(letters) for _ in range(length))
        return result_str


# if __name__ == "__main__":
    # Throughput (number of requests/sec) vs. N (DB size)
    # Latency (time to complete a request) vs. Throughput
    # N_range = [7, 15, 31, 63, 127, 255, 511, 1023, 2047, 4095]
    # throughput_arr = list()
    # latency_arr = list()
    # for cur_N in N_range:
    #     server, client = Server(cur_N), Client()
    #     actions = 0
    #     total_time = 0
    #     finish_time = time.time() + INTERVAL
    #     while time.time() < finish_time:
    #         cur_id1, cur_id2 = random.randint(0, 10000),\
    #                            random.randint(0, 10000)
    #         client.store_data(server, cur_id1, DEFAULT_DATA)
    #         client.store_data(server, cur_id2, DEFAULT_DATA)
    #         client.retrieve_data(server, cur_id1)
    #         client.retrieve_data(server, cur_id2)
    #         client.delete_data(server, cur_id2)
    #         actions += 5
    #     cur_throughput = actions / INTERVAL
    #     print('Current Throughput = {}'.format(cur_throughput))
    #     throughput_arr.append(cur_throughput)
    #     cur_latency = INTERVAL / actions
    #     print('Current Latency = {}'.format(cur_latency))
    #     latency_arr.append(cur_latency)
    # print('Throughput array: {}'.format(throughput_arr))
    # print('Latency array: {}'.format(latency_arr))
    #
    # plt.figure(1)
    # plt.plot(N_range, throughput_arr)
    # plt.xlabel('DB Size'), plt.ylabel('Throughput')
    # plt.title('Throughput (number of requests/sec) vs. N (DB size)')
    # plt.grid(True)
    # plt.tight_layout()
    # # plt.savefig('Throughput vs DB Size')
    # plt.show()
    #
    # plt.figure(2)
    # plt.plot(throughput_arr, latency_arr, color='red')
    # plt.xlabel('Throughput'), plt.ylabel('Latency')
    # plt.title('Latency (time to complete a request) vs. Throughput')
    # plt.grid(True)
    # plt.tight_layout()
    # # plt.savefig('Latency vs Throughput')
    # plt.show()

    # ======= BASIC CHECKS ======= #
    # my_server = Server(7)
    # print('Server Height = {}'.format(my_server.height))
    # my_client = Client()
    # print(my_server._tree.tree_arr)
    # my_client.store_data(my_server, 1, 'aaaa')
    # print(my_server._tree.root.value)
    # print('== AFTER Storing Key 1 ==')
    # my_client._print_node_values(my_server._tree.root)
    # print()
    # my_client._print_node_values(my_server._tree.root.left)
    # print()
    # my_client._print_node_values(my_server._tree.root.right)
    # print('== FINISH Pushing After Key 1 ==\n')
    #
    # my_client.store_data(my_server, 2, 'bbbb')
    # print('== AFTER Storing Key 2 ==')
    # my_client._print_node_values(my_server._tree.root)
    # print()
    # my_client._print_node_values(my_server._tree.root.left)
    # print()
    # my_client._print_node_values(my_server._tree.root.right)
    # print('== FINISH Pushing After Key 2 ==\n')
    #
    # my_client.store_data(my_server, 3, 'cccc')
    # print('== AFTER Storing Key 3 ==')
    # my_client._print_node_values(my_server._tree.root)
    # print()
    # my_client._print_node_values(my_server._tree.root.left)
    # print()
    # my_client._print_node_values(my_server._tree.root.right)
    # print('== FINISH Pushing After Key 3 ==\n')
    #
    # # print('Memory = {}'.format(my_client.memory))
    # x = my_client.retrieve_data(my_server, 1)
    # y = my_client.retrieve_data(my_server, 2)
    # z = my_client.retrieve_data(my_server, 3)
    # print('== RETRIEVE ==')
    # print(x)
    # print(y)
    # print(z)
    #
    # my_client.delete_data(my_server, 1)
    # my_client.delete_data(my_server, 2)
    # my_client.delete_data(my_server, 3)
    # print()
    #
    # print('== AFTER DELETE ==')
    # my_client._print_node_values(my_server._tree.root)
    # print('== FINISH DELETE ==')
