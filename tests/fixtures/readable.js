// Inventory helpers.
class Inventory {
  constructor(items) {
    this.items = items;
  }

  total() {
    let sum = 0;
    for (const item of this.items) {
      sum += item.price * item.quantity;
    }
    return sum;
  }
}

function formatPrice(amount) {
  if (amount < 0) {
    return "invalid";
  }
  return "$" + amount.toFixed(2);
}

const double = (value) => value * 2;
var legacy = function () {
  return double(21);
};

const inventory = new Inventory([{ price: 2, quantity: 3 }]);
let label = inventory.total() > 5 ? "large" : "small";
while (false) {}
console.log(formatPrice(inventory.total()), label, legacy());
