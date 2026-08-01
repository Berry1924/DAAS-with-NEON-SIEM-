from collections import deque


class MemoryQueue:
    def __init__(self): self.items = deque()
    def put(self, record): self.items.append(record)
    def take(self, limit): return [self.items.popleft() for _ in range(min(limit, len(self.items)))]
    def requeue_front(self, records): self.items.extendleft(reversed(records))
    def __len__(self): return len(self.items)
