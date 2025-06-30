import React from 'react';

const UserData = ({ userDivData, userDiv, setUserDiv }) => {
  return (
    <>
      {/* Overlay */}
      <div className={`${userDiv} fixed inset-0 bg-zinc-900 bg-opacity-80 flex justify-center items-center z-50`}>
        {/* Modal Box */}
        <div className="bg-black bg-opacity-90 p-6 rounded-xl shadow-2xl w-full max-w-md relative text-yellow-300">
          {/* Close Button */}
          <button
            onClick={() => setUserDiv("hidden")}
            className="absolute top-3 right-3 text-yellow-300 hover:text-red-500 text-xl font-bold"
          >
            &times;
          </button>

          <h2 className="text-2xl font-bold mb-5 text-center">User Details</h2>

          {/* User Info Fields */}
          <div className="flex flex-col gap-4 text-base">
            <div>
              <label htmlFor="name" className="block font-semibold mb-1">Name</label>
              <input
                type="text"
                id="name"
                value={userDivData?.username || ""}
                disabled
                className="w-full p-2 rounded-md bg-zinc-900 text-yellow-300"
              />
            </div>

            <div>
              <label htmlFor="email" className="block font-semibold mb-1">Email</label>
              <input
                type="email"
                id="email"
                value={userDivData?.email || ""}
                disabled
                className="w-full p-2 rounded-md bg-zinc-900 text-yellow-300"
              />
            </div>

            <div>
              <label htmlFor="address" className="block font-semibold mb-1">Address</label>
              <input
                type="text"
                id="address"
                value={userDivData?.address || ""}
                disabled
                className="w-full p-2 rounded-md bg-zinc-900 text-yellow-300"
              />
            </div>
          </div>

          <button
            onClick={() => setUserDiv("hidden")}
            className="mt-6 w-full bg-yellow-300 hover:bg-yellow-400 text-black font-semibold py-2 px-4 rounded-md text-base"
          >
            Close
          </button>
        </div>
      </div>
    </>
  );
};

export default UserData;
